function sanitizeText(s) {
  if (typeof s !== "string") return "";
  return s.replace(/\0/g, "").trim().replace(/[<>]/g, "");
}

function isValidEmail(email) {
  if (typeof email !== "string") return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
}

module.exports = { sanitizeText, isValidEmail };
