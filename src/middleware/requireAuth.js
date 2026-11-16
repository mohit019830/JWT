const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ error: "No authorization header provided" });
  }

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ error: "Token format should be: Bearer <token>" });
  }

  const token = parts[1];

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWTSECRET);
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token has expired" });
    }
    return res.status(401).json({ error: "Token is not valid" });
  }

  const user = await prisma.user.findUnique({
    where: { id: decoded.id }
  });

  if (!user) {
    return res.status(401).json({ error: "User belonging to this token no longer exists" });
  }

  req.user = decoded;
  next();
}

module.exports = requireAuth;

