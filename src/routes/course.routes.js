const express = require("express");
const router = express.Router();
const {
  getAllCourses,
  getCourseById,
  getMyCourses,
  enrollCourse,
  markLessonComplete,
  createCourse,
  getAdminCourses,
  updateCourse,
  deleteCourse
} = require("../controllers/course.controller");
const { protect, adminOnly } = require("../middleware/auth.middleware");

// Public routes
router.get("/", getAllCourses);
router.get("/:id", getCourseById);

// Protected student routes
router.get("/my/list", protect, getMyCourses);
router.post("/enroll/:courseId", protect, enrollCourse);
router.post("/:courseId/lesson/:lessonId/complete", protect, markLessonComplete);

// Admin routes
router.post("/admin/create", protect, adminOnly, createCourse);
router.get("/admin/all", protect, adminOnly, getAdminCourses);
router.put("/admin/:id", protect, adminOnly, updateCourse);
router.delete("/admin/:id", protect, adminOnly, deleteCourse);

// Admin Enrollment & Progress
const { adminEnrollStudent, getPlatformProgress } = require("../controllers/course.controller");

router.post("/admin/enroll-student", protect, adminOnly, adminEnrollStudent);
router.get("/admin/platform/progress", protect, adminOnly, getPlatformProgress);

module.exports = router;
