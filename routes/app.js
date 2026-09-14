const express = require("express");
const { sendView } = require("../utils/views");
const creditService = require("../services/credits");

module.exports = function createAppRoutes({ pool, requireAuth }) {
  const router = express.Router();

  router.get("/", requireAuth, (req, res) => sendView(res, "index.html"));

  router.get("/me", requireAuth, async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT id, email, role FROM users WHERE id = $1",
        [req.session.userId]
      );
      if (!result.rows[0]) {
        return res.status(404).json({ error: "User not found." });
      }
      const creditBalance = await creditService.getBalance(req.session.userId);
      return res.json({ ...result.rows[0], creditBalance });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Could not load user." });
    }
  });

  return router;
};
