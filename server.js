const express = require("express");
const zipcodes = require("zipcodes");
const tzlookup = require("tz-lookup");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));

app.get("/time/:zip", (req, res) => {
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
  } catch (error) {
    return res.status(500).json({ error: "Couldn't determine timezone for this ZIP code." });
  }

  const now = new Date();

  const formatted = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    dateStyle: "full",
    timeStyle: "long"
  }).format(now);

  res.json({
    zip,
    city: location.city,
    state: location.state,
    timezone,
    currentDateTime: formatted,
    timestamp: now.toISOString()
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "timezone-app" });
});

app.listen(PORT, () => {
  console.log(`Timezone app running at http://localhost:${PORT}`);
});
