const rateLimit = require("express-rate-limit");

function createLimiter(windowMs, limit, message) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    message
  });
}

module.exports = {
  login: createLimiter(15 * 60 * 1000, 10, "Too many login attempts. Try again in 15 minutes."),
  verify: createLimiter(10 * 60 * 1000, 10, "Too many verification attempts. Try again later."),
  resend: createLimiter(10 * 60 * 1000, 3, "Too many resend requests. Try again in 10 minutes."),
  emailChange: createLimiter(15 * 60 * 1000, 5, "Too many email change attempts. Try again in 15 minutes.")
};
