const courseService = require("../services/course.service");
const enrollmentService = require("../services/enrollment.service");

exports.getCourses = async (req, res) => {
  try {
    const courses = await courseService.getAllCourses(req.query);
    res.json(courses);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getCourse = async (req, res) => {
  try {
    const course = await courseService.getCourseById(req.params.id);
    if (!course) return res.status(404).json({ msg: "Course not found" });
    res.json(course);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getMyCourses = async (req, res) => {
  try {
    const enrollments = await enrollmentService.getStudentEnrollments(req.user.id);
    res.json(enrollments);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

exports.enrollCourse = async (req, res) => {
  try {
    const enrollment = await enrollmentService.enroll(req.user.id, req.params.courseId);
    res.status(201).json(enrollment);
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
};

exports.markLessonComplete = async (req, res) => {
    try {
        const enrollment = await enrollmentService.updateProgress(req.user.id, req.params.courseId, req.params.lessonId);
        res.json(enrollment);
    } catch (err) {
        res.status(400).json({ msg: err.message });
    }
};

exports.createCourse = async (req, res) => {
  try {
    const course = await courseService.createCourse(req.body);
    res.status(201).json(course);
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
};

exports.updateCourse = async (req, res) => {
  try {
    const course = await courseService.updateCourse(req.params.id, req.body);
    res.json(course);
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
};

exports.deleteCourse = async (req, res) => {
  try {
    await courseService.deleteCourse(req.params.id);
    res.json({ msg: "Course removed" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

exports.adminEnrollStudent = async (req, res) => {
    try {
        const { studentId, courseId } = req.body;
        const enrollment = await enrollmentService.enroll(studentId, courseId);
        res.status(201).json(enrollment);
    } catch (err) {
        res.status(400).json({ msg: err.message });
    }
};

exports.getPlatformProgress = async (req, res) => {
    try {
        const progress = await enrollmentService.getPlatformStats();
        res.json(progress);
    } catch (err) {
        res.status(500).json({ msg: "Server error" });
    }
};
