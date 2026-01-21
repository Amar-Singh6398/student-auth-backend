const User = require("../models/User");
const jwt = require("jsonwebtoken");

// Helper to generate JWT
const generateToken = (user) => 
  jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

// REGISTER
exports.register = async (req, res) => {
  const { email, password, role = "student" } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: "Email and password are required" });
  }

  try {
    // Check if user exists
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: "User already exists" });

    // Create new user (password will be hashed automatically via pre-save hook)
    user = new User({ email, password, role });
    await user.save();

    // Generate token
    const token = generateToken(user);

    res.status(201).json({
      token,
      user: { email: user.email, role: user.role }
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

// LOGIN
exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: "Email and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    // Compare password (assuming matchPassword method exists in User model)
    const isMatch = await user.matchPassword(password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = generateToken(user);

    res.status(200).json({
      token,
      user: { email: user.email, role: user.role }
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

// GET PROFILE
exports.getProfile = async (req, res) => {
  res.status(200).json({ user: req.user });
};
