const express = require("express");

module.exports = function createBillingWebhookRoutes({ billingService }) {
  const router = express.Router();

  router.post(
    "/webhooks/stripe",
    express.raw({ type: "application/json" }),
    async (req, res) => {
      let event;
      try {
        event = billingService.constructWebhookEvent(
          req.body,
          req.headers["stripe-signature"]
        );
      } catch (error) {
        console.error("Invalid Stripe webhook:", error.message);
        return res.status(400).send("Invalid webhook signature.");
      }

      try {
        await billingService.processWebhookEvent(event);
        return res.json({ received: true });
      } catch (error) {
        console.error("Could not process Stripe webhook:", error);
        return res.status(500).send("Could not process webhook.");
      }
    }
  );

  return router;
};
