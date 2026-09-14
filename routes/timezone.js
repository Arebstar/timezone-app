const express = require("express");
const zipcodes = require("zipcodes");
const tzlookup = require("tz-lookup");
const creditService = require("../services/credits");

module.exports = function createTimezoneRoutes({ requireAuth }) {
  const router = express.Router();

  router.get("/time/:zip", requireAuth, async (req, res) => {
    const zip = String(req.params.zip || "").trim();
    if (!/^\d{5}$/.test(zip)) {
      return res.status(400).json({ error: "ZIP code must be exactly 5 digits." });
    }

    const location = zipcodes.lookup(zip);
    if (!location) {
      return res.status(404).json({ error: "ZIP code not found." });
    }

    let timezone;
    try {
      timezone = tzlookup(location.latitude, location.longitude);
    } catch {
      return res.status(500).json({ error: "Could not determine timezone." });
    }

    const now = new Date();
    const currentDateTime = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      dateStyle: "full",
      timeStyle: "long"
    }).format(now);

    let creditsRemaining;
    try {
      creditsRemaining = await creditService.consumeCredits(
        req.session.userId,
        1,
        `ZIP timezone lookup: ${zip}`
      );
    } catch (error) {
      if (error.code === "INSUFFICIENT_CREDITS") {
        return res.status(402).json({
          error: "You need at least 1 credit to look up a ZIP code.",
          creditsRemaining: 0
        });
      }
      console.error(error);
      return res.status(500).json({ error: "Could not use a credit for this lookup." });
    }

    return res.json({
      zip,
      city: location.city,
      state: location.state,
      timezone,
      currentDateTime,
      timestamp: now.toISOString(),
      creditsRemaining
    });
  });

  return router;
};
