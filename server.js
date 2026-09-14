const path = require("path");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);

const pool = require("./db/pool");
const { requireAuth, requireAdmin } = require("./middleware/auth");
const limits = require("./middleware/rate-limits");
const emailService = require("./services/email");
const billingService = require("./services/billing");
const createBillingWebhookRoutes = require("./routes/billing-webhook");
const createBillingRoutes = require("./routes/billing");
const createHealthRoutes = require("./routes/health");
const createAuthRoutes = require("./routes/auth");
const createAppRoutes = require("./routes/app");
const createAccountRoutes = require("./routes/account");
const createAdminRoutes = require("./routes/admin");
const createTimezoneRoutes = require("./routes/timezone");

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET is required");

const app = express();
const port = Number(process.env.PORT || 3000);
const secureCookie =
  String(process.env.COOKIE_SECURE || "false").toLowerCase() === "true";

app.set("trust proxy", 1);
app.use(createBillingWebhookRoutes({ billingService }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use("/assets", express.static(path.join(__dirname, "public")));
app.use(session({
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
}));

app.use(createHealthRoutes({ pool }));
app.use(createAuthRoutes({ pool, emailService, limits }));
app.use(createAppRoutes({ pool, requireAuth }));
app.use(createAccountRoutes({ pool, requireAuth, emailService, limits }));
app.use(createBillingRoutes({ requireAuth, billingService }));
app.use(createAdminRoutes({ pool, requireAdmin }));
app.use(createTimezoneRoutes({ requireAuth }));

app.listen(port, "0.0.0.0", () => {
  console.log(`Timezone app running at http://localhost:${port}`);
});
