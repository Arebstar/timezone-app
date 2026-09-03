const path = require("path");
const crypto = require("crypto");
const express = require("express");
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

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "mailpit",
  port: Number(process.env.SMTP_PORT || 1025),
  secure: false
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

const sendView = (res, name) => {
  res.sendFile(path.join(__dirname, "views", name));
};

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
      "no-reply@timezone.test",

    to: user.email,

    subject:
      "Your Timezone App login code",

    text:
      `Your login code is ${code}. ` +
      `It expires in 10 minutes.`
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

app.post("/login", async (req, res) => {
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

      res.send(`
        <!doctype html>

        <html lang="en">

        <head>
          <meta charset="utf-8">

          <meta
            name="viewport"
            content="width=device-width, initial-scale=1"
          >

          <title>
            Users — Timezone App
          </title>

          <link
            rel="stylesheet"
            href="/assets/style.css"
          >
        </head>

        <body>

          <main>

            <section class="card">

              <h1>Users</h1>

              <p>
                <a href="/">
                  Back to app
                </a>
              </p>

              <div
                style="overflow-x:auto;"
              >

                <table
                  border="1"
                  cellpadding="10"
                  cellspacing="0"
                >

                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Created</th>
                    </tr>
                  </thead>

                  <tbody>
                    ${rows}
                  </tbody>

                </table>

              </div>

            </section>

          </main>

        </body>

        </html>
      `);
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