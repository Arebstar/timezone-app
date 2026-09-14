const pool = require("../db/pool");

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  return res.redirect("/login");
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");

  try {
    const result = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [req.session.userId]
    );
    if (!result.rows[0] || result.rows[0].role !== "admin") {
      return res.status(403).send("Forbidden");
    }
    return next();
  } catch (error) {
    console.error(error);
    return res.status(500).send("Could not verify admin access.");
  }
}

module.exports = { requireAuth, requireAdmin };
