const jwt = require("jsonwebtoken");
const User = require("../models/user");
const redisClient = require("../config/redis");

const userMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: "Token not provided" });
    }

    // Verify token
    const payload = jwt.verify(token, process.env.JWT_KEY);
    const { _id } = payload;

    if (!_id) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    // Check if token is in Redis blocklist (i.e., logged out)
    const isBlocked = await redisClient.exists(`token:${token}`);
    if (isBlocked) {
      return res.status(401).json({ message: "Token is blocked (user logged out)" });
    }

    // Find user from DB
    const user = await User.findById(_id);
    if (!user) {
      return res.status(401).json({ message: "User does not exist" });
    }

    // Attach selected fields to req.result
    req.result = {
      _id: user._id,
      firstName: user.firstName,
      emailId: user.emailId,
      role: user.role
    };

    next();
  } catch (err) {
    console.error("Middleware error:", err.message);
    return res.status(401).json({ message: err.message || "Unauthorized" });
  }
};

module.exports = userMiddleware;
