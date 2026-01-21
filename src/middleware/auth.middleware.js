const jwt = require("jsonwebtoken");
const User = require("../models/User");

/**
 * Protect routes by verifying JWT token.
 * If valid, attaches user object to req.user
 */
exports.protect = async (req, res, next) => {
  try {
    // 1️⃣ Get token from Authorization header
    // Format: "Bearer <token>"
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ msg: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // 2️⃣ Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3️⃣ Find user in DB (exclude password)
    const user = await User.findById(decoded.id).select("-password");
    if (!user) return res.status(401).json({ msg: "User not found" });

    // 4️⃣ Attach user to request object
    req.user = user;

    // 5️⃣ Proceed to the next middleware or route
    next();
  } catch (err) {
    // Handle JWT errors
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ msg: "Token expired" });
    }
    res.status(401).json({ msg: "Token invalid" });
  }
};
