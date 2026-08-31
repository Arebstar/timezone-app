const path = require("path");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const zipcodes = require("zipcodes");
const tzlookup = require("tz-lookup");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const secureCookie = String(process.env.COOKIE_SECURE || "false").toLowerCase() === "true";

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET is required");

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use("/assets", express.static(path.join(__dirname, "public")));
app.use(session({
  store: new pgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: secureCookie, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const sendView = (res, name) => res.sendFile(path.join(__dirname, "views", name));
const requireAuth = (req, res, next) => req.session.userId ? next() : res.redirect("/login");

app.get("/health", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ status: "ok", database: "ok" }); }
  catch { res.status(500).json({ status: "error", database: "unavailable" }); }
});

app.get("/register", (req, res) => req.session.userId ? res.redirect("/") : sendView(res, "register.html"));
app.post("/register", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !email.includes("@")) return res.status(400).send("Enter a valid email address.");
  if (password.length < 8) return res.status(400).send("Password must be at least 8 characters.");
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query("INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id,email", [email, hash]);
    req.session.userId = result.rows[0].id;
    req.session.email = result.rows[0].email;
    res.redirect("/");
  } catch (e) {
    if (e.code === "23505") return res.status(409).send("An account with that email already exists.");
    console.error(e); res.status(500).send("Could not create account.");
  }
});

app.get("/login", (req, res) => req.session.userId ? res.redirect("/") : sendView(res, "login.html"));
app.post("/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  try {
    const result = await pool.query("SELECT id,email,password_hash FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).send("Invalid email or password.");
    req.session.userId = user.id; req.session.email = user.email; res.redirect("/");
  } catch (e) { console.error(e); res.status(500).send("Could not log in."); }
});

app.post("/logout", (req, res) => req.session.destroy(() => { res.clearCookie("connect.sid"); res.redirect("/login"); }));
app.get("/", requireAuth, (req, res) => sendView(res, "index.html"));
app.get("/me", requireAuth, (req, res) => res.json({ id: req.session.userId, email: req.session.email }));
app.get("/time/:zip", requireAuth, (req, res) => {
  const zip = String(req.params.zip || "").trim();
  if (!/^\d{5}$/.test(zip)) return res.status(400).json({ error: "ZIP code must be exactly 5 digits." });
  const location = zipcodes.lookup(zip);
  if (!location) return res.status(404).json({ error: "ZIP code not found." });
  let timezone;
  try { timezone = tzlookup(location.latitude, location.longitude); }
  catch { return res.status(500).json({ error: "Could not determine timezone." }); }
  const now = new Date();
  res.json({
    zip, city: location.city, state: location.state, timezone,
    currentDateTime: new Intl.DateTimeFormat("en-US", { timeZone: timezone, dateStyle: "full", timeStyle: "long" }).format(now),
    timestamp: now.toISOString()
  });
});

app.listen(PORT, "0.0.0.0", () => console.log(`Timezone app running at http://localhost:${PORT}`));
