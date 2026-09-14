const express = require("express");

module.exports = function createBillingRoutes({ requireAuth, billingService }) {
  const router = express.Router();

  router.post("/billing/checkout", requireAuth, async (req, res) => {
    try {
      const checkout = await billingService.createCheckoutSession(req.session.userId);
      return res.redirect(303, checkout.url);
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not start Stripe Checkout.");
    }
  });

  router.post("/billing/portal", requireAuth, async (req, res) => {
    try {
      const portal = await billingService.createPortalSession(req.session.userId);
      return res.redirect(303, portal.url);
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not open the billing portal.");
    }
  });

  return router;
};
