const path = require("path");
const fs = require("fs/promises");

function sendView(res, name) {
  res.sendFile(path.join(__dirname, "..", "views", name));
}

async function sendTemplate(res, name, values) {
  const template = await fs.readFile(
    path.join(__dirname, "..", "views", name),
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

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

module.exports = { sendView, sendTemplate, escapeHtml };
