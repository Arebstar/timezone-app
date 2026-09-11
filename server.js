const path = require("path");
const fs = require("fs/promises");
const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const zipcodes = require("zipcodes");
const tzlookup = require("tz-lookup");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const secureCookie =
  String(process.env.COOKIE_SECURE || "false").toLowerCase() === "true";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}

// const mailer = nodemailer.createTransport({
//   host: process.env.SMTP_HOST || "mailpit",
//   port: Number(process.env.SMTP_PORT || 1025),
//   secure: false
// });

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,

  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  "/assets",
  express.static(path.join(__dirname, "public"))
);

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true
    }),

    secret: process.env.SESSION_SECRET,

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: secureCookie,
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many login attempts. Try again in 15 minutes."
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many verification attempts. Try again later."
});

const resendLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many resend requests. Try again in 10 minutes."
});

const emailChangeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many email change attempts. Try again in 15 minutes."
});

const sendView = (res, name) => {
  res.sendFile(path.join(__dirname, "views", name));
};

async function sendTemplate(res, name, values) {
  const template = await fs.readFile(
    path.join(__dirname, "views", name),
    "utf8"
  );

  const html = template.replace(
    /{{([A-Z_]+)}}/g,
    (placeholder, key) => Object.hasOwn(values, key)
      ? String(values[key])
      : placeholder
  );

  res.type("html").send(html);
}

const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }

  return res.redirect("/login");
};

async function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }

  try {
    const result = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [req.session.userId]
    );

    const user = result.rows[0];

    if (!user || user.role !== "admin") {
      return res.status(403).send("Forbidden");
    }

    next();
  } catch (error) {
    console.error(error);
    res.status(500).send("Could not verify admin access.");
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function sendLoginCode(user) {
  const code = String(
    crypto.randomInt(100000, 1000000)
  );

  const codeHash = await bcrypt.hash(code, 10);

  await pool.query(
    `
      UPDATE login_codes
      SET used_at = NOW()
      WHERE user_id = $1
        AND used_at IS NULL
    `,
    [user.id]
  );

  await pool.query(
    `
      INSERT INTO login_codes (
        user_id,
        code_hash,
        expires_at
      )
      VALUES (
        $1,
        $2,
        NOW() + INTERVAL '10 minutes'
      )
    `,
    [user.id, codeHash]
  );

  await mailer.sendMail({
    from:
      process.env.MAIL_FROM ||
      "no-reply@workmansuccess.com",

    to: user.email,

    subject:
      "Your Timezone App login code",

    text:
      `Your login code is ${code}. ` +
      `It expires in 10 minutes.`
  });
}

async function sendEmailChangeCode(userId, newEmail) {
  const code = String(crypto.randomInt(100000, 1000000));
  const codeHash = await bcrypt.hash(code, 10);

  await pool.query(
    `
      UPDATE email_change_codes
      SET used_at = NOW()
      WHERE user_id = $1
        AND used_at IS NULL
    `,
    [userId]
  );

  await pool.query(
    `
      INSERT INTO email_change_codes (
        user_id,
        new_email,
        code_hash,
        expires_at
      )
      VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')
    `,
    [userId, newEmail, codeHash]
  );

  await mailer.sendMail({
    from: process.env.MAIL_FROM || "no-reply@workmansuccess.com",
    to: newEmail,
    subject: "Verify your new Timezone App email",
    text: `Your email change code is ${code}. It expires in 10 minutes.`
  });
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

/*
|--------------------------------------------------------------------------
| Health
|--------------------------------------------------------------------------
*/

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "ok"
    });
  } catch {
    res.status(500).json({
      status: "error",
      database: "unavailable"
    });
  }
});

/*
|--------------------------------------------------------------------------
| Registration
|--------------------------------------------------------------------------
*/

app.get("/register", (req, res) => {
  if (req.session.userId) {
    return res.redirect("/");
  }

  sendView(res, "register.html");
});

app.post("/register", async (req, res) => {
  const email = String(req.body.email || "")
    .trim()
    .toLowerCase();

  const password = String(
    req.body.password || ""
  );

  if (!email || !email.includes("@")) {
    return res
      .status(400)
      .send("Enter a valid email address.");
  }

  if (password.length < 8) {
    return res
      .status(400)
      .send(
        "Password must be at least 8 characters."
      );
  }

  try {
    const hash = await bcrypt.hash(
      password,
      12
    );

    const result = await pool.query(
      `
        INSERT INTO users (
          email,
          password_hash
        )
        VALUES ($1, $2)
        RETURNING id, email
      `,
      [email, hash]
    );

    /*
      Registration still logs the user in
      immediately for now.

      We can later make registration require
      email verification too.
    */
    req.session.userId =
      result.rows[0].id;

    req.session.email =
      result.rows[0].email;

    res.redirect("/");
  } catch (error) {
    if (error.code === "23505") {
      return res
        .status(409)
        .send(
          "An account with that email already exists."
        );
    }

    console.error(error);

    res
      .status(500)
      .send("Could not create account.");
  }
});

/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/

app.get("/login", (req, res) => {
  if (req.session.userId) {
    return res.redirect("/");
  }

  sendView(res, "login.html");
});

app.post("/login", loginLimiter, async (req, res) => {
  const email = String(req.body.email || "")
    .trim()
    .toLowerCase();

  const password = String(
    req.body.password || ""
  );

  try {
    const result = await pool.query(
      `
        SELECT
          id,
          email,
          password_hash
        FROM users
        WHERE email = $1
      `,
      [email]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res
        .status(401)
        .send(
          "Invalid email or password."
        );
    }

    /*
      Password is correct.

      Do NOT fully authenticate yet.

      Generate/send the 2FA code first.
    */
    await sendLoginCode(user);

    req.session.pendingUserId = user.id;
    req.session.pendingEmail = user.email;
    req.session.verifyAttempts = 0;
    req.session.lastCodeSentAt = Date.now();

    delete req.session.userId;
    delete req.session.email;

    res.redirect("/verify");
  } catch (error) {
    console.error(error);

    res
      .status(500)
      .send("Could not log in.");
  }
});

/*
|--------------------------------------------------------------------------
| 2FA Verification
|--------------------------------------------------------------------------
*/

app.get("/verify", (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect("/login");
  }

  sendView(res, "verify.html");
});

app.post(
  "/verify",
  verifyLimiter,
  async (req, res) => {
    if (!req.session.pendingUserId) {
      return res.redirect("/login");
    }

    const code = String(
      req.body.code || ""
    ).trim();

    try {
      const result = await pool.query(
        `
          SELECT
            id,
            code_hash
          FROM login_codes
          WHERE user_id = $1
            AND used_at IS NULL
            AND expires_at > NOW()
          ORDER BY created_at DESC
          LIMIT 1
        `,
        [req.session.pendingUserId]
      );

      const challenge =
        result.rows[0];

      if (
        !challenge ||
        !(await bcrypt.compare(
          code,
          challenge.code_hash
        ))
      ) {
        req.session.verifyAttempts =
          Number(req.session.verifyAttempts || 0) + 1;

        if (req.session.verifyAttempts >= 5) {
          delete req.session.pendingUserId;
          delete req.session.pendingEmail;
          delete req.session.verifyAttempts;
          delete req.session.lastCodeSentAt;

          return res
            .status(429)
            .send("Too many incorrect codes. Please log in again.");
        }

        return res
          .status(401)
          .send(
            "Invalid or expired code."
          );
      }

      await pool.query(
        `
          UPDATE login_codes
          SET used_at = NOW()
          WHERE id = $1
        `,
        [challenge.id]
      );

      /*
        2FA succeeded.

        Now the user becomes fully
        authenticated.
      */
      req.session.userId =
        req.session.pendingUserId;

      req.session.email =
        req.session.pendingEmail;

      delete req.session.pendingUserId;
      delete req.session.pendingEmail;
      delete req.session.verifyAttempts;
      delete req.session.lastCodeSentAt;

      res.redirect("/");
    } catch (error) {
      console.error(error);

      res
        .status(500)
        .send(
          "Could not verify login code."
        );
    }
  }
);

app.post(
  "/verify/resend",
  resendLimiter,
  async (req, res) => {
    if (!req.session.pendingUserId) {
      return res.redirect("/login");
    }

    const resendCooldownMs = 60 * 1000;
    const lastCodeSentAt = Number(req.session.lastCodeSentAt || 0);
    const remainingMs = resendCooldownMs - (Date.now() - lastCodeSentAt);

    if (remainingMs > 0) {
      return res
        .status(429)
        .send(
          `Please wait ${Math.ceil(remainingMs / 1000)} seconds before requesting another code.`
        );
    }

    try {
      const result = await pool.query(
        "SELECT id, email FROM users WHERE id = $1",
        [req.session.pendingUserId]
      );

      const user = result.rows[0];

      if (!user) {
        return res.redirect("/login");
      }

      await sendLoginCode(user);

      req.session.verifyAttempts = 0;
      req.session.lastCodeSentAt = Date.now();

      return res.redirect("/verify?resent=1");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not resend login code.");
    }
  }
);

/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

/*
|--------------------------------------------------------------------------
| Main authenticated app
|--------------------------------------------------------------------------
*/

app.get(
  "/",
  requireAuth,
  (req, res) => {
    sendView(res, "index.html");
  }
);

app.get(
  "/me",
  requireAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              email,
              role
            FROM users
            WHERE id = $1
          `,
          [req.session.userId]
        );

      const user =
        result.rows[0];

      if (!user) {
        return res
          .status(404)
          .json({
            error:
              "User not found."
          });
      }

      res.json(user);
    } catch (error) {
      console.error(error);

      res
        .status(500)
        .json({
          error:
            "Could not load user."
        });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Account and email changes
|--------------------------------------------------------------------------
*/

app.get("/account", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email FROM users WHERE id = $1",
      [req.session.userId]
    );
    const user = result.rows[0];

    if (!user) {
      return req.session.destroy(() => res.redirect("/login"));
    }

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

app.post(
  "/account/email",
  requireAuth,
  emailChangeLimiter,
  async (req, res) => {
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

      if (!user) {
        return req.session.destroy(() => res.redirect("/login"));
      }

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

      await sendEmailChangeCode(user.id, newEmail);
      req.session.pendingNewEmail = newEmail;
      req.session.emailChangeAttempts = 0;
      req.session.lastEmailChangeCodeSentAt = Date.now();

      return res.redirect("/account");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not start the email change.");
    }
  }
);

app.post(
  "/account/email/verify",
  requireAuth,
  verifyLimiter,
  async (req, res) => {
    if (!req.session.pendingNewEmail) {
      return res.redirect("/account");
    }

    const code = String(req.body.code || "").trim();

    try {
      const result = await pool.query(
        `
          SELECT id, new_email, code_hash
          FROM email_change_codes
          WHERE user_id = $1
            AND new_email = $2
            AND used_at IS NULL
            AND expires_at > NOW()
          ORDER BY created_at DESC
          LIMIT 1
        `,
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
          delete req.session.pendingNewEmail;
          delete req.session.emailChangeAttempts;
          delete req.session.lastEmailChangeCodeSentAt;
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
      delete req.session.pendingNewEmail;
      delete req.session.emailChangeAttempts;
      delete req.session.lastEmailChangeCodeSentAt;

      if (oldEmail && oldEmail !== challenge.new_email) {
        mailer.sendMail({
          from: process.env.MAIL_FROM || "no-reply@workmansuccess.com",
          to: oldEmail,
          subject: "Your Timezone App email was changed",
          text: `Your account email was changed from ${oldEmail} to ${challenge.new_email}. If you did not make this change, contact support immediately.`
        }).catch((error) => console.error("Could not send email change notification:", error));
      }

      return res.redirect("/account?changed=1");
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).send("An account with that email already exists.");
      }

      console.error(error);
      return res.status(500).send("Could not verify the email change.");
    }
  }
);

app.post(
  "/account/email/resend",
  requireAuth,
  resendLimiter,
  async (req, res) => {
    const newEmail = req.session.pendingNewEmail;

    if (!newEmail) {
      return res.redirect("/account");
    }

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

      await sendEmailChangeCode(req.session.userId, newEmail);
      req.session.emailChangeAttempts = 0;
      req.session.lastEmailChangeCodeSentAt = Date.now();
      return res.redirect("/account?resent=1");
    } catch (error) {
      console.error(error);
      return res.status(500).send("Could not resend the verification code.");
    }
  }
);

app.post("/account/email/cancel", requireAuth, async (req, res) => {
  try {
    await pool.query(
      "UPDATE email_change_codes SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
      [req.session.userId]
    );
    delete req.session.pendingNewEmail;
    delete req.session.emailChangeAttempts;
    delete req.session.lastEmailChangeCodeSentAt;
    return res.redirect("/account");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Could not cancel the email change.");
  }
});

/*
|--------------------------------------------------------------------------
| Admin
|--------------------------------------------------------------------------
*/

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              email,
              role,
              created_at
            FROM users
            ORDER BY created_at DESC
          `
        );

      const rows =
        result.rows
          .map(
            (user) => `
              <tr>
                <td>${user.id}</td>

                <td>
                  ${escapeHtml(
                    user.email
                  )}
                </td>

                <td>
                  ${escapeHtml(
                    user.role
                  )}
                </td>

                <td>
                  ${new Date(
                    user.created_at
                  ).toLocaleString()}
                </td>
              </tr>
            `
          )
          .join("");

      await sendTemplate(res, "admin-users.html", { USER_ROWS: rows });
    } catch (error) {
      console.error(error);

      res
        .status(500)
        .send(
          "Could not load users."
        );
    }
  }
);

/*
|--------------------------------------------------------------------------
| Timezone API
|--------------------------------------------------------------------------
*/

app.get(
  "/time/:zip",
  requireAuth,
  (req, res) => {
    const zip = String(
      req.params.zip || ""
    ).trim();

    if (!/^\d{5}$/.test(zip)) {
      return res
        .status(400)
        .json({
          error:
            "ZIP code must be exactly 5 digits."
        });
    }

    const location =
      zipcodes.lookup(zip);

    if (!location) {
      return res
        .status(404)
        .json({
          error:
            "ZIP code not found."
        });
    }

    let timezone;

    try {
      timezone = tzlookup(
        location.latitude,
        location.longitude
      );
    } catch {
      return res
        .status(500)
        .json({
          error:
            "Could not determine timezone."
        });
    }

    const now = new Date();

    res.json({
      zip,
      city: location.city,
      state: location.state,
      timezone,

      currentDateTime:
        new Intl.DateTimeFormat(
          "en-US",
          {
            timeZone: timezone,
            dateStyle: "full",
            timeStyle: "long"
          }
        ).format(now),

      timestamp:
        now.toISOString()
    });
  }
);

/*
|--------------------------------------------------------------------------
| Start server
|--------------------------------------------------------------------------
*/

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Timezone app running at http://localhost:${PORT}`
    );
  }
);
