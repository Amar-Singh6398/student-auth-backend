const express = require("express");
const router = express.Router();
const { register, login, getProfile, getStudents, deleteUser, updateUser } = require("../controllers/auth.controller");
const { forgotPassword } = require("../controllers/forgot.password");
const { resetPassword } = require("../controllers/reset.password");
const { protect, adminOnly } = require("../middleware/auth.middleware");

router.post("/register", register);
router.post("/login", login);
router.get("/me", protect, getProfile);

// ADMIN: Manage Students
router.get("/students", protect, adminOnly, getStudents);
router.post("/students", protect, adminOnly, register);
router.delete("/students/:id", protect, adminOnly, deleteUser);
router.put("/students/:id", protect, adminOnly, updateUser);

// Password Reset
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

module.exports = router;
