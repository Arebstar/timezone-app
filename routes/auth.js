const express = require("express");
const bcrypt = require("bcryptjs");
const { sendView } = require("../utils/views");
const creditService = require("../services/credits");

module.exports = function createAuthRoutes({ pool, emailService, limits }) {
  const router = express.Router();

  router.get("/register", (req, res) => {
    if (req.session.userId) return res.redirect("/");
    return sendView(res, "register.html");
  });

  router.post("/register", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !email.includes("@")) {
      return res.status(400).send("Enter a valid email address.");
    }
    if (password.length < 8) {
      return res.status(400).send("Password must be at least 8 characters.");
    }

    try {
      const hash = await bcrypt.hash(password, 12);
      const client = await pool.connect();
      let result;
      try {
        await client.query("BEGIN");
        result = await client.query(
          `INSERT INTO users (email, password_hash)
           VALUES ($1, $2) RETURNING id, email`,
          [email, hash]
        );
        await creditService.grantSignupCredits(client, result.rows[0].id);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
      req.session.userId = result.rows[0].id;
      req.session.email = result.rows[0].email;
      return res.redirect("/");
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).send("An account with that email already exists.");
      }
      console.error(error);
      return res.status(500).send("Could not create account.");
    }
  });

  router.get("/login", (req, res) => {
    if (req.session.userId) return res.redirect("/");
    return sendView(res, "login.html");
  });

  router.post("/login", limits.login, async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    try {
      const result = await pool.query(
        "SELECT id, email, password_hash FROM users WHERE email = $1",
        [email]
      );
      const user = result.rows[0];
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).send("Invalid email or password.");
      }

      await emailService.sendLoginCode(user);
      req.session.pendingUserId = user.id;
      req.session.pendingEmail = user.email;
      req.session.verifyAttempts = 0;
      req.session.lastCodeSentAt = Date.now();
      delete req.session.userId;
      delete req.session.email;
      return res.redirect("/verify");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not log in.");
    }
  });

  router.get("/verify", (req, res) => {
    if (!req.session.pendingUserId) return res.redirect("/login");
    return sendView(res, "verify.html");
  });

  router.post("/verify", limits.verify, async (req, res) => {
    if (!req.session.pendingUserId) return res.redirect("/login");
    const code = String(req.body.code || "").trim();
    try {
      const result = await pool.query(
        `SELECT id, code_hash FROM login_codes
         WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1`,
        [req.session.pendingUserId]
      );
      const challenge = result.rows[0];
      if (!challenge || !(await bcrypt.compare(code, challenge.code_hash))) {
        req.session.verifyAttempts = Number(req.session.verifyAttempts || 0) + 1;
        if (req.session.verifyAttempts >= 5) {
          clearPendingLogin(req.session);
          return res.status(429).send("Too many incorrect codes. Please log in again.");
        }
        return res.status(401).send("Invalid or expired code.");
      }

      await pool.query("UPDATE login_codes SET used_at = NOW() WHERE id = $1", [challenge.id]);
      req.session.userId = req.session.pendingUserId;
      req.session.email = req.session.pendingEmail;
      clearPendingLogin(req.session);
      return res.redirect("/");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not verify login code.");
    }
  });

  router.post("/verify/resend", limits.resend, async (req, res) => {
    if (!req.session.pendingUserId) return res.redirect("/login");
    const remainingMs = 60 * 1000 -
      (Date.now() - Number(req.session.lastCodeSentAt || 0));
    if (remainingMs > 0) {
      return res.status(429).send(
        `Please wait ${Math.ceil(remainingMs / 1000)} seconds before requesting another code.`
      );
    }

    try {
      const result = await pool.query(
        "SELECT id, email FROM users WHERE id = $1",
        [req.session.pendingUserId]
      );
      if (!result.rows[0]) return res.redirect("/login");
      await emailService.sendLoginCode(result.rows[0]);
      req.session.verifyAttempts = 0;
      req.session.lastCodeSentAt = Date.now();
      return res.redirect("/verify?resent=1");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not resend login code.");
    }
  });

  router.post("/logout", (req, res) => {
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.redirect("/login");
    });
  });

  return router;
};

function clearPendingLogin(session) {
  delete session.pendingUserId;
  delete session.pendingEmail;
  delete session.verifyAttempts;
  delete session.lastCodeSentAt;
}
