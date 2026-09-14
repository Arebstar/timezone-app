const express = require("express");
const { sendTemplate, escapeHtml } = require("../utils/views");

module.exports = function createAdminRoutes({ pool, requireAdmin }) {
  const router = express.Router();

  router.get("/admin/users", requireAdmin, async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT id, email, role, created_at FROM users ORDER BY created_at DESC"
      );
      const rows = result.rows.map((user) => `
        <tr>
          <td>${user.id}</td>
          <td>${escapeHtml(user.email)}</td>
          <td>${escapeHtml(user.role)}</td>
          <td>${new Date(user.created_at).toLocaleString()}</td>
        </tr>
      `).join("");
      await sendTemplate(res, "admin-users.html", { USER_ROWS: rows });
    } catch (error) {
      console.error(error);
      res.status(500).send("Could not load users.");
    }
  });

  return router;
};
