const express = require("express");
const bcrypt = require("bcryptjs");
const { sendTemplate, escapeHtml } = require("../utils/views");

module.exports = function createAccountRoutes({
  pool,
  requireAuth,
  emailService,
  limits
}) {
  const router = express.Router();

  router.get("/account", requireAuth, async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT id, email FROM users WHERE id = $1",
        [req.session.userId]
      );
      const user = result.rows[0];
      if (!user) return req.session.destroy(() => res.redirect("/login"));

      const message = req.query.changed === "1"
        ? "Your email address has been changed."
        : req.query.resent === "1"
          ? "A new verification code was sent."
          : "";
      await renderAccount(res, user, req.session.pendingNewEmail, message);
    } catch (error) {
      console.error(error);
      res.status(500).send("Could not load account.");
    }
  });

  router.post("/account/email", requireAuth, limits.emailChange, async (req, res) => {
    const newEmail = String(req.body.newEmail || "").trim().toLowerCase();
    const currentPassword = String(req.body.currentPassword || "");
    if (newEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
      return res.status(400).send("Enter a valid new email address.");
    }

    try {
      const result = await pool.query(
        "SELECT id, email, password_hash FROM users WHERE id = $1",
        [req.session.userId]
      );
      const user = result.rows[0];
      if (!user) return req.session.destroy(() => res.redirect("/login"));
      if (!(await bcrypt.compare(currentPassword, user.password_hash))) {
        return res.status(401).send("Current password is incorrect.");
      }
      if (newEmail === user.email) {
        return res.status(400).send("That is already your current email address.");
      }

      const existing = await pool.query(
        "SELECT 1 FROM users WHERE email = $1 AND id <> $2",
        [newEmail, user.id]
      );
      if (existing.rowCount > 0) {
        return res.status(409).send("An account with that email already exists.");
      }

      await emailService.sendEmailChangeCode(user.id, newEmail);
      req.session.pendingNewEmail = newEmail;
      req.session.emailChangeAttempts = 0;
      req.session.lastEmailChangeCodeSentAt = Date.now();
      return res.redirect("/account");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not start the email change.");
    }
  });

  router.post("/account/email/verify", requireAuth, limits.verify, async (req, res) => {
    if (!req.session.pendingNewEmail) return res.redirect("/account");
    const code = String(req.body.code || "").trim();

    try {
      const result = await pool.query(
        `SELECT id, new_email, code_hash FROM email_change_codes
         WHERE user_id = $1 AND new_email = $2
           AND used_at IS NULL AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1`,
        [req.session.userId, req.session.pendingNewEmail]
      );
      const challenge = result.rows[0];
      if (!challenge || !(await bcrypt.compare(code, challenge.code_hash))) {
        req.session.emailChangeAttempts =
          Number(req.session.emailChangeAttempts || 0) + 1;
        if (req.session.emailChangeAttempts >= 5) {
          await pool.query(
            "UPDATE email_change_codes SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
            [req.session.userId]
          );
          clearPendingEmailChange(req.session);
          return res.status(429).send("Too many incorrect codes. Start the email change again.");
        }
        return res.status(401).send("Invalid or expired code.");
      }

      const oldEmailResult = await pool.query(
        "SELECT email FROM users WHERE id = $1",
        [req.session.userId]
      );
      const oldEmail = oldEmailResult.rows[0]?.email;
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const claimed = await client.query(
          "UPDATE email_change_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL RETURNING id",
          [challenge.id]
        );
        if (claimed.rowCount !== 1) {
          throw new Error("Email change challenge was already used");
        }
        await client.query(
          "UPDATE users SET email = $1 WHERE id = $2",
          [challenge.new_email, req.session.userId]
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }

      req.session.email = challenge.new_email;
      clearPendingEmailChange(req.session);
      if (oldEmail && oldEmail !== challenge.new_email) {
        emailService.sendEmailChangeNotification(oldEmail, challenge.new_email)
          .catch((error) => console.error("Could not send email change notification:", error));
      }
      return res.redirect("/account?changed=1");
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).send("An account with that email already exists.");
      }
      console.error(error);
      return res.status(500).send("Could not verify the email change.");
    }
  });

  router.post("/account/email/resend", requireAuth, limits.resend, async (req, res) => {
    const newEmail = req.session.pendingNewEmail;
    if (!newEmail) return res.redirect("/account");
    const remainingMs = 60 * 1000 -
      (Date.now() - Number(req.session.lastEmailChangeCodeSentAt || 0));
    if (remainingMs > 0) {
      return res.status(429).send(
        `Please wait ${Math.ceil(remainingMs / 1000)} seconds before requesting another code.`
      );
    }

    try {
      const userResult = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [req.session.userId]
      );
      if (!userResult.rows[0]) {
        return req.session.destroy(() => res.redirect("/login"));
      }
      await emailService.sendEmailChangeCode(req.session.userId, newEmail);
      req.session.emailChangeAttempts = 0;
      req.session.lastEmailChangeCodeSentAt = Date.now();
      return res.redirect("/account?resent=1");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not resend the verification code.");
    }
  });

  router.post("/account/email/cancel", requireAuth, async (req, res) => {
    try {
      await pool.query(
        "UPDATE email_change_codes SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
        [req.session.userId]
      );
      clearPendingEmailChange(req.session);
      return res.redirect("/account");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not cancel the email change.");
    }
  });

  return router;
};

function clearPendingEmailChange(session) {
  delete session.pendingNewEmail;
  delete session.emailChangeAttempts;
  delete session.lastEmailChangeCodeSentAt;
}

async function renderAccount(res, user, pendingEmail, message = "", isError = false) {
  await sendTemplate(res, "account.html", {
    CURRENT_EMAIL: escapeHtml(user.email),
    PENDING_EMAIL: escapeHtml(pendingEmail || ""),
    CHANGE_HIDDEN: pendingEmail ? "hidden" : "",
    VERIFY_HIDDEN: pendingEmail ? "" : "hidden",
    FEEDBACK_HIDDEN: message ? "" : "hidden",
    FEEDBACK_CLASS: isError ? "error" : "notice",
    FEEDBACK: escapeHtml(message)
  });
}
