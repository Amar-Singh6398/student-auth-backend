const express = require("express");
const router = express.Router();
const {
  getCourses,
  getCourse,
  getMyCourses,
  enrollCourse,
  markLessonComplete,
  createCourse,
  updateCourse,
  deleteCourse,
  adminEnrollStudent,
  getPlatformProgress
} = require("../controllers/course.controller");
const { protect, adminOnly } = require("../middleware/auth.middleware");

// Public routes
router.get("/", getCourses);
router.get("/:id", getCourse);

// Protected student routes
router.get("/my/list", protect, getMyCourses);
router.post("/enroll/:courseId", protect, enrollCourse);
router.post("/:courseId/lesson/:lessonId/complete", protect, markLessonComplete);

// Admin routes
router.post("/admin/create", protect, adminOnly, createCourse);
router.get("/admin/all", protect, adminOnly, getCourses); // Using getCourses for admin list
router.put("/admin/:id", protect, adminOnly, updateCourse);
router.delete("/admin/:id", protect, adminOnly, deleteCourse);

// Admin Enrollment & Progress
router.post("/admin/enroll-student", protect, adminOnly, adminEnrollStudent);
router.get("/admin/platform/progress", protect, adminOnly, getPlatformProgress);

module.exports = router;
