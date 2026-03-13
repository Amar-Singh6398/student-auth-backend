const User = require("../models/User");
const Course = require("../models/Course");
const Enrollment = require("../models/Enrollment");

exports.getAdminStats = async (req, res) => {
  try {
    const totalStudents = await User.countDocuments({ role: "student" });
    const totalCourses = await Course.countDocuments();
    const totalEnrollments = await Enrollment.countDocuments();
    
    const recentEnrollments = await Enrollment.find()
      .populate("student", "name email")
      .populate("course", "title")
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      totalStudents,
      totalCourses,
      totalEnrollments,
      recentEnrollments
    });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getStudentStats = async (req, res) => {
  try {
    const enrollments = await Enrollment.find({ student: req.user.id }).populate("course");
    const completedCourses = enrollments.filter(e => e.progress === 100).length;
    
    res.json({
      enrolledCourses: enrollments.length,
      completedCourses,
      recentActivity: enrollments.slice(0, 3)
    });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};
