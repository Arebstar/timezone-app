const Stripe = require("stripe");
const pool = require("../db/pool");
const creditService = require("./credits");

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;
const appId = "timezone-app";

function requireConfiguration() {
  if (!stripe || !process.env.STRIPE_PRO_PRICE_ID || !process.env.APP_BASE_URL) {
    throw new Error("Stripe billing is not configured");
  }
}

async function createCheckoutSession(userId) {
  requireConfiguration();
  const userResult = await pool.query(
    `SELECT u.email, b.stripe_customer_id, b.stripe_subscription_id, b.status
     FROM users u
     LEFT JOIN billing_accounts b ON b.user_id = u.id
     WHERE u.id = $1`,
    [userId]
  );
  const user = userResult.rows[0];
  if (!user) throw new Error("User not found");
  if (user.stripe_subscription_id && !["canceled", "incomplete_expired"].includes(user.status)) {
    const error = new Error("User already has a Stripe subscription");
    error.code = "ALREADY_SUBSCRIBED";
    throw error;
  }

  let customerId = user.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({
      email: user.email,
      metadata: { app_id: appId, user_id: String(userId) }
    });
    customerId = customer.id;
    await pool.query(
      `INSERT INTO billing_accounts (user_id, stripe_customer_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE
       SET stripe_customer_id = EXCLUDED.stripe_customer_id, updated_at = NOW()`,
      [userId, customerId]
    );
  }

  return stripe.checkout.sessions.create({
    mode: "subscription",
    customer: customerId,
    line_items: [{ price: process.env.STRIPE_PRO_PRICE_ID, quantity: 1 }],
    success_url: `${process.env.APP_BASE_URL}/account?checkout=success`,
    cancel_url: `${process.env.APP_BASE_URL}/account?checkout=cancelled`,
    client_reference_id: String(userId),
    metadata: { app_id: appId, user_id: String(userId) },
    subscription_data: {
      metadata: { app_id: appId, user_id: String(userId) }
    }
  });
}

async function createPortalSession(userId) {
  requireConfiguration();
  const result = await pool.query(
    "SELECT stripe_customer_id FROM billing_accounts WHERE user_id = $1",
    [userId]
  );
  if (!result.rows[0]?.stripe_customer_id) throw new Error("Stripe customer not found");
  return stripe.billingPortal.sessions.create({
    customer: result.rows[0].stripe_customer_id,
    return_url: `${process.env.APP_BASE_URL}/account`
  });
}

function constructWebhookEvent(body, signature) {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    throw new Error("Stripe webhook is not configured");
  }
  return stripe.webhooks.constructEvent(
    body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET
  );
}

async function processWebhookEvent(event) {
  let subscription = null;
  let invoice = null;

  if (event.type === "invoice.paid") {
    invoice = event.data.object;
    if (!["subscription_create", "subscription_cycle"].includes(invoice.billing_reason)) {
      return recordIgnoredEvent(event);
    }
    const subscriptionId = getInvoiceSubscriptionId(invoice);
    if (!subscriptionId) return recordIgnoredEvent(event);
    subscription = await stripe.subscriptions.retrieve(subscriptionId);
  } else if (event.type.startsWith("customer.subscription.")) {
    subscription = event.data.object;
  } else if (event.type === "checkout.session.completed") {
    const checkout = event.data.object;
    if (checkout.metadata?.app_id !== appId || !checkout.subscription) {
      return recordIgnoredEvent(event);
    }
    subscription = await stripe.subscriptions.retrieve(checkout.subscription);
  } else {
    return recordIgnoredEvent(event);
  }

  if (!isRelevantSubscription(subscription)) {
    return recordIgnoredEvent(event);
  }

  const userId = Number(subscription.metadata.user_id);
  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return recordIgnoredEvent(event);
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const inserted = await client.query(
      `INSERT INTO stripe_events (event_id, event_type)
       VALUES ($1, $2) ON CONFLICT (event_id) DO NOTHING RETURNING event_id`,
      [event.id, event.type]
    );
    if (!inserted.rows[0]) {
      await client.query("ROLLBACK");
      return false;
    }

    const item = subscription.items.data.find(
      (entry) => entry.price?.id === process.env.STRIPE_PRO_PRICE_ID
    );
    const periodEnd = subscription.current_period_end || item?.current_period_end;
    await client.query(
      `INSERT INTO billing_accounts
         (user_id, stripe_customer_id, stripe_subscription_id, plan, status, current_period_end)
       VALUES ($1, $2, $3, 'pro', $4, $5)
       ON CONFLICT (user_id) DO UPDATE SET
         stripe_customer_id = EXCLUDED.stripe_customer_id,
         stripe_subscription_id = EXCLUDED.stripe_subscription_id,
         plan = EXCLUDED.plan,
         status = EXCLUDED.status,
         current_period_end = EXCLUDED.current_period_end,
         updated_at = NOW()`,
      [
        userId,
        subscription.customer,
        subscription.id,
        subscription.status,
        periodEnd ? new Date(periodEnd * 1000) : null
      ]
    );

    if (invoice) {
      const expiresAt = periodEnd ? addUtcMonth(new Date(periodEnd * 1000)) : null;
      await creditService.grantCredits(client, {
        userId,
        amount: 10,
        sourceType: "stripe_invoice",
        sourceId: invoice.id,
        expiresAt,
        transactionType: "subscription_grant",
        description: "Pro monthly credits"
      });
    }

    await client.query("COMMIT");
    return true;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function isRelevantSubscription(subscription) {
  return subscription?.metadata?.app_id === appId &&
    subscription.items?.data?.some(
      (item) => item.price?.id === process.env.STRIPE_PRO_PRICE_ID
    );
}

function getInvoiceSubscriptionId(invoice) {
  const value = invoice.subscription || invoice.parent?.subscription_details?.subscription;
  return typeof value === "string" ? value : value?.id;
}

function addUtcMonth(date) {
  const result = new Date(date);
  result.setUTCMonth(result.getUTCMonth() + 1);
  return result;
}

async function recordIgnoredEvent(event) {
  await pool.query(
    `INSERT INTO stripe_events (event_id, event_type)
     VALUES ($1, $2) ON CONFLICT (event_id) DO NOTHING`,
    [event.id, event.type]
  );
  return false;
}

module.exports = {
  createCheckoutSession,
  createPortalSession,
  constructWebhookEvent,
  processWebhookEvent
};
