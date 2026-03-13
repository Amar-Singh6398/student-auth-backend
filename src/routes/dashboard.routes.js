const express = require("express");
const router = express.Router();
const { getStudentStats, getAdminStats } = require("../controllers/dashboard.controller");
const { protect } = require("../middleware/auth.middleware");

// Basic stats (combination or dependent on role)
router.get("/stats", protect, (req, res, next) => {
    if (req.user.role === 'admin') return getAdminStats(req, res, next);
    return getStudentStats(req, res, next);
});

// Student stats
router.get("/student", protect, getStudentStats);

// Admin stats
router.get("/admin", protect, getAdminStats);

module.exports = router;
