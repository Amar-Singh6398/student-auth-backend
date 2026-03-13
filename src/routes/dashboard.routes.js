const express = require("express");
const router = express.Router();
const { getStudentStats, getAdminStats } = require("../controllers/dashboard.controller");
const { protect } = require("../middleware/auth.middleware");

// Student stats
router.get("/student", protect, getStudentStats);

// Admin stats
router.get("/admin", protect, getAdminStats);

module.exports = router;
