const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const pool = require("../db/pool");

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
const from = process.env.MAIL_FROM || "no-reply@workmansuccess.com";

async function sendLoginCode(user) {
  const code = String(crypto.randomInt(100000, 1000000));
  const codeHash = await bcrypt.hash(code, 10);
  await pool.query(
    "UPDATE login_codes SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
    [user.id]
  );
  await pool.query(
    `INSERT INTO login_codes (user_id, code_hash, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`,
    [user.id, codeHash]
  );
  await mailer.sendMail({
    from,
    to: user.email,
    subject: "Your Timezone App login code",
    text: `Your login code is ${code}. It expires in 10 minutes.`
  });
}

async function sendEmailChangeCode(userId, newEmail) {
  const code = String(crypto.randomInt(100000, 1000000));
  const codeHash = await bcrypt.hash(code, 10);
  await pool.query(
    "UPDATE email_change_codes SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
    [userId]
  );
  await pool.query(
    `INSERT INTO email_change_codes (user_id, new_email, code_hash, expires_at)
     VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
    [userId, newEmail, codeHash]
  );
  await mailer.sendMail({
    from,
    to: newEmail,
    subject: "Verify your new Timezone App email",
    text: `Your email change code is ${code}. It expires in 10 minutes.`
  });
}

async function sendEmailChangeNotification(oldEmail, newEmail) {
  await mailer.sendMail({
    from,
    to: oldEmail,
    subject: "Your Timezone App email was changed",
    text: `Your account email was changed from ${oldEmail} to ${newEmail}. If you did not make this change, contact support immediately.`
  });
}

module.exports = { sendLoginCode, sendEmailChangeCode, sendEmailChangeNotification };
