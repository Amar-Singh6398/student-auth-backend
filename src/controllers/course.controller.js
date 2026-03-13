const Course = require("../models/Course");
const Enrollment = require("../models/Enrollment");
const User = require("../models/User");

// ──────────────────────────────────────────────
// PUBLIC: GET all published courses
// ──────────────────────────────────────────────
exports.getAllCourses = async (req, res) => {
  try {
    const courses = await Course.find({ status: "published" }).select(
      "-modules"
    );
    res.json({ courses });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// PUBLIC: GET single course by ID
// ──────────────────────────────────────────────
exports.getCourseById = async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ msg: "Course not found" });
    res.json({ course });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// PROTECTED: GET courses enrolled by the logged-in student
// ──────────────────────────────────────────────
exports.getMyCourses = async (req, res) => {
  try {
    const enrollments = await Enrollment.find({ student: req.user._id })
      .populate("course", "title instructor image category lessons totalLessons rating")
      .sort({ lastAccessedAt: -1 });

    const courses = enrollments
      .filter((e) => e.course) // Security against deleted courses
      .map((e) => ({
        _id: e.course._id,
        title: e.course.title,
        instructor: e.course.instructor,
        image: e.course.image,
        category: e.course.category,
        rating: e.course.rating,
        progress: e.progress,
        lessons: e.course.totalLessons,
        completed: e.lessonsCompleted,
        lastAccessed: formatTimeAgo(e.lastAccessedAt),
        enrollmentId: e._id,
      }));

    res.json({ courses });
  } catch (err) {
    console.error("GET MY COURSES ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// PROTECTED: Enroll student in a course
// ──────────────────────────────────────────────
exports.enrollCourse = async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ msg: "Course not found" });

    const existing = await Enrollment.findOne({
      student: req.user._id,
      course: courseId,
    });
    if (existing) return res.status(400).json({ msg: "Already enrolled" });

    const enrollment = await Enrollment.create({
      student: req.user._id,
      course: courseId,
    });

    // increment enrollment count
    await Course.findByIdAndUpdate(courseId, { $inc: { enrollmentCount: 1 } });

    res.status(201).json({ msg: "Enrolled successfully", enrollment });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// PROTECTED: Mark a lesson as complete
// ──────────────────────────────────────────────
exports.markLessonComplete = async (req, res) => {
  try {
    const { courseId, lessonId } = req.params;

    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ msg: "Course not found" });

    const enrollment = await Enrollment.findOne({
      student: req.user._id,
      course: courseId,
    });
    if (!enrollment) return res.status(403).json({ msg: "Not enrolled" });

    // Check if lesson already marked
    const alreadyDone = enrollment.lessonProgress.find(
      (lp) => lp.lessonId.toString() === lessonId && lp.completed
    );
    if (!alreadyDone) {
      enrollment.lessonProgress.push({
        lessonId,
        completed: true,
        completedAt: new Date(),
      });
      enrollment.lessonsCompleted = enrollment.lessonProgress.filter(
        (lp) => lp.completed
      ).length;
    }

    // Recalculate progress %
    const totalLessons = course.modules.reduce(
      (sum, m) => sum + m.lessons.length,
      0
    );
    enrollment.progress =
      totalLessons > 0
        ? Math.round((enrollment.lessonsCompleted / totalLessons) * 100)
        : 0;

    if (enrollment.progress === 100) enrollment.completedAt = new Date();
    enrollment.lastAccessedAt = new Date();

    await enrollment.save();

    res.json({
      msg: "Lesson marked complete",
      progress: enrollment.progress,
      lessonsCompleted: enrollment.lessonsCompleted,
    });
  } catch (err) {
    console.error("MARK LESSON ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Create a course
// ──────────────────────────────────────────────
exports.createCourse = async (req, res) => {
  try {
    const { title, description, instructor, image, category, tech, price, modules } =
      req.body;

    if (!title) return res.status(400).json({ msg: "Title is required" });

    // Calculate total lessons
    const totalLessons = (modules || []).reduce(
      (sum, m) => sum + (m.lessons || []).length,
      0
    );

    const course = await Course.create({
      title,
      description,
      instructor,
      image,
      category,
      tech,
      price,
      modules: modules || [],
      totalLessons,
    });

    res.status(201).json({ msg: "Course created", course });
  } catch (err) {
    console.error("CREATE COURSE ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Get all courses (including drafts)
// ──────────────────────────────────────────────
exports.getAdminCourses = async (req, res) => {
  try {
    const courses = await Course.find().sort({ createdAt: -1 });
    res.json({ courses });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Update a course
// ──────────────────────────────────────────────
exports.updateCourse = async (req, res) => {
  try {
    const course = await Course.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!course) return res.status(404).json({ msg: "Course not found" });
    res.json({ msg: "Course updated", course });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Delete a course
// ──────────────────────────────────────────────
exports.deleteCourse = async (req, res) => {
  try {
    await Course.findByIdAndDelete(req.params.id);
    await Enrollment.deleteMany({ course: req.params.id });
    res.json({ msg: "Course deleted" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Enroll a specific student in a course
// ──────────────────────────────────────────────
exports.adminEnrollStudent = async (req, res) => {
  try {
    const { courseId, studentId } = req.body;
    
    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ msg: "Course not found" });

    const student = await User.findById(studentId);
    if (!student) return res.status(404).json({ msg: "Student not found" });

    const existing = await Enrollment.findOne({
      student: studentId,
      course: courseId,
    });
    if (existing) return res.status(400).json({ msg: "Already enrolled" });

    const enrollment = await Enrollment.create({
      student: studentId,
      course: courseId,
    });

    await Course.findByIdAndUpdate(courseId, { $inc: { enrollmentCount: 1 } });

    res.status(201).json({ msg: "Student enrolled successfully", enrollment });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Get all student progress for the entire platform
// ──────────────────────────────────────────────
exports.getPlatformProgress = async (req, res) => {
  try {
    const enrollments = await Enrollment.find()
      .populate("student", "name email")
      .populate("course", "title category totalLessons")
      .sort({ student: 1 });

    const validEnrollments = enrollments.filter(e => e.student && e.course);
    res.json({ progress: validEnrollments });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// Helper: format time ago string
// ──────────────────────────────────────────────
function formatTimeAgo(date) {
  if (!date) return "Never";
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return mins <= 1 ? "Just now" : `${mins} mins ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs === 1 ? "1 hour ago" : `${hrs} hours ago`;
  const days = Math.floor(hrs / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}
