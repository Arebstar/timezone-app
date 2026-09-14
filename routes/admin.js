const express = require("express");
const crypto = require("crypto");
const { sendTemplate, escapeHtml } = require("../utils/views");
const creditService = require("../services/credits");

module.exports = function createAdminRoutes({ pool, requireAdmin }) {
  const router = express.Router();

  router.get("/admin/users", requireAdmin, async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT u.id, u.email, u.role, u.created_at,
          COALESCE(SUM(g.remaining_amount) FILTER (
            WHERE g.expires_at IS NULL OR g.expires_at > NOW()
          ), 0)::integer AS credit_balance
        FROM users u
        LEFT JOIN credit_grants g ON g.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `);
      const rows = result.rows.map((user) => `
        <tr>
          <td>${user.id}</td>
          <td>${escapeHtml(user.email)}</td>
          <td>${escapeHtml(user.role)}</td>
          <td>${user.credit_balance}</td>
          <td>${new Date(user.created_at).toLocaleString()}</td>
          <td>
            <form class="credit-gift-form" method="post" action="/admin/users/${user.id}/credits">
              <input name="amount" type="number" min="1" max="1000" value="5" required aria-label="Credits">
              <input name="reason" type="text" maxlength="200" placeholder="Reason" required aria-label="Reason">
              <button type="submit">Gift</button>
            </form>
          </td>
        </tr>
      `).join("");
      await sendTemplate(res, "admin-users.html", { USER_ROWS: rows });
    } catch (error) {
      console.error(error);
      res.status(500).send("Could not load users.");
    }
  });

  router.post("/admin/users/:id/credits", requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);
    const amount = Number(req.body.amount);
    const reason = String(req.body.reason || "").trim();
    if (!Number.isSafeInteger(userId) || !Number.isInteger(amount) ||
        amount < 1 || amount > 1000 || !reason || reason.length > 200) {
      return res.status(400).send("Enter 1–1000 credits and a reason.");
    }

    try {
      await creditService.grantCredits(pool, {
        userId,
        amount,
        sourceType: "admin_gift",
        sourceId: crypto.randomUUID(),
        transactionType: "admin_gift",
        description: reason,
        createdByUserId: req.session.userId
      });
      return res.redirect("/admin/users");
    } catch (error) {
      if (error.code === "23503") return res.status(404).send("User not found.");
      console.error(error);
      return res.status(500).send("Could not gift credits.");
    }
  });

  return router;
};
