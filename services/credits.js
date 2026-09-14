const pool = require("../db/pool");

async function grantCredits(db, {
  userId,
  amount,
  sourceType,
  sourceId,
  expiresAt = null,
  transactionType,
  description,
  createdByUserId = null
}) {
  const result = await db.query(
    `INSERT INTO credit_grants
       (user_id, original_amount, remaining_amount, source_type, source_id, expires_at)
     VALUES ($1, $2, $2, $3, $4, $5)
     ON CONFLICT (source_type, source_id) DO NOTHING
     RETURNING id`,
    [userId, amount, sourceType, sourceId, expiresAt]
  );
  if (!result.rows[0]) return false;

  await db.query(
    `INSERT INTO credit_transactions
       (user_id, grant_id, amount, transaction_type, description, created_by_user_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId, result.rows[0].id, amount, transactionType, description, createdByUserId]
  );
  return true;
}

async function grantSignupCredits(db, userId) {
  await db.query(
    `INSERT INTO billing_accounts (user_id)
     VALUES ($1) ON CONFLICT (user_id) DO NOTHING`,
    [userId]
  );
  return grantCredits(db, {
    userId,
    amount: 5,
    sourceType: "signup",
    sourceId: `signup:${userId}`,
    transactionType: "signup_grant",
    description: "Free plan signup credits"
  });
}

async function getBalance(userId) {
  const result = await pool.query(
    `SELECT COALESCE(SUM(remaining_amount), 0)::integer AS balance
     FROM credit_grants
     WHERE user_id = $1
       AND remaining_amount > 0
       AND (expires_at IS NULL OR expires_at > NOW())`,
    [userId]
  );
  return result.rows[0].balance;
}

async function consumeCredits(userId, amount, description) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const grants = await client.query(
      `SELECT id, remaining_amount
       FROM credit_grants
       WHERE user_id = $1 AND remaining_amount > 0
         AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY expires_at ASC NULLS LAST, created_at ASC, id ASC
       FOR UPDATE`,
      [userId]
    );
    const balance = grants.rows.reduce((sum, grant) => sum + grant.remaining_amount, 0);
    if (balance < amount) {
      const error = new Error("Not enough credits");
      error.code = "INSUFFICIENT_CREDITS";
      throw error;
    }

    let remaining = amount;
    for (const grant of grants.rows) {
      if (remaining === 0) break;
      const used = Math.min(remaining, grant.remaining_amount);
      await client.query(
        "UPDATE credit_grants SET remaining_amount = remaining_amount - $1 WHERE id = $2",
        [used, grant.id]
      );
      await client.query(
        `INSERT INTO credit_transactions
           (user_id, grant_id, amount, transaction_type, description)
         VALUES ($1, $2, $3, 'usage', $4)`,
        [userId, grant.id, -used, description]
      );
      remaining -= used;
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { grantCredits, grantSignupCredits, getBalance, consumeCredits };
