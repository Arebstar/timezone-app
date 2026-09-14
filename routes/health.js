const express = require("express");

module.exports = function createHealthRoutes({ pool }) {
  const router = express.Router();

  router.get("/health", async (req, res) => {
    try {
      await pool.query("SELECT 1");
      res.json({ status: "ok", database: "ok" });
    } catch {
      res.status(500).json({ status: "error", database: "unavailable" });
    }
  });

  return router;
};
