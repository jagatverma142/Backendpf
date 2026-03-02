function errorHandler(err, req, res, next) {
  const status = err.statusCode || 500;
  const message = status === 500 ? "Internal server error" : (err.message || "Error");
  if (status === 500) console.error(err);

  res.status(status).json({ ok: false, error: { code: err.code || "ERROR", message } });
}
module.exports = { errorHandler };
