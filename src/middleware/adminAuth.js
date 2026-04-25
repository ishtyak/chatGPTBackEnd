const jwt = require("jsonwebtoken");

module.exports = function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Admin token required." });
  }

  try {
    const payload = jwt.verify(token, process.env.ADMIN_JWT_SECRET);
    if (!payload.isAdmin) {
      return res.status(403).json({ error: "Not an admin token." });
    }
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired admin token." });
  }
};
