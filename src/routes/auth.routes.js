const express = require("express");
const router = express.Router();

const { register, login, getProfile } = require("../controllers/auth.controller");
const {forgotPassword} = require("../controllers/forgot.password")
const {resetPassword} = require("../controllers/reset.password")

const { protect, adminOnly } = require("../middleware/auth.middleware");

router.post("/register", register);
router.post("/login", login);
router.get("/me", protect, getProfile);

// ADMIN: Manage Users
const User = require("../models/User");

// List all students
router.get("/students", protect, adminOnly, async (req, res) => {
  try {
    const students = await User.find({ role: "student" }).select("-password");
    res.json(students);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// Admin creates student
router.post("/students/create", protect, adminOnly, register);

// Admin deletes student
router.delete("/students/:id", protect, adminOnly, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ msg: "Student removed" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// Admin updates student
router.put("/students/:id", protect, adminOnly, async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { name, email }, { new: true });
    res.json(user);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});


// 🔥 NEW ROUTES
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);


module.exports = router;
