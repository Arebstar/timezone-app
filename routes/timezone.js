const express = require("express");
const zipcodes = require("zipcodes");
const tzlookup = require("tz-lookup");

module.exports = function createTimezoneRoutes({ requireAuth }) {
  const router = express.Router();

  router.get("/time/:zip", requireAuth, (req, res) => {
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
    return res.json({
      zip,
      city: location.city,
      state: location.state,
      timezone,
      currentDateTime: new Intl.DateTimeFormat("en-US", {
        timeZone: timezone,
        dateStyle: "full",
        timeStyle: "long"
      }).format(now),
      timestamp: now.toISOString()
    });
  });

  return router;
};
