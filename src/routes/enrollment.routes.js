const express = require("express");
const router = express.Router();
const { enrollCourse, getMyCourses } = require("../controllers/course.controller");
const { protect } = require("../middleware/auth.middleware");

// Student enrollments
router.get("/", protect, getMyCourses);
router.post("/:courseId", protect, enrollCourse);

module.exports = router;
