const Enrollment = require("../models/Enrollment");
const { Quiz, QuizAttempt } = require("../models/Quiz");
const Course = require("../models/Course");
const User = require("../models/User");

// ──────────────────────────────────────────────
// STUDENT: Personal dashboard stats
// ──────────────────────────────────────────────
exports.getStudentStats = async (req, res) => {
  try {
    const studentId = req.user._id;

    const enrollments = await Enrollment.find({ student: studentId });

    const coursesInProgress = enrollments.filter(
      (e) => e.progress > 0 && e.progress < 100
    ).length;

    const overallProgress =
      enrollments.length > 0
        ? Math.round(
            enrollments.reduce((sum, e) => sum + e.progress, 0) /
              enrollments.length
          )
        : 0;

    // Count passed quizzes
    const quizAttempts = await QuizAttempt.find({ student: studentId });
    const assessmentsPassed = quizAttempts.filter((a) => a.passed).length;

    // Compute weekly study hours (rough estimate: each completed lesson = 30 mins)
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - 7);

    let weeklyMinutes = 0;
    for (const enrollment of enrollments) {
      for (const lp of enrollment.lessonProgress || []) {
        if (lp.completed && lp.completedAt >= weekStart) {
          weeklyMinutes += 30;
        }
      }
    }
    const hoursSpent = `${Math.round(weeklyMinutes / 60)}h`;

    res.json({
      coursesInProgress,
      hoursSpent,
      assessmentsPassed,
      overallProgress: `${overallProgress}%`,
    });
  } catch (err) {
    console.error("STUDENT STATS ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

// ──────────────────────────────────────────────
// ADMIN: Platform overview stats
// ──────────────────────────────────────────────
exports.getAdminStats = async (req, res) => {
  try {
    const totalStudents = await User.countDocuments({ role: "student" });
    const totalCourses = await Course.countDocuments();
    const activeStudents = await Enrollment.distinct("student", {
      lastAccessedAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
    });

    // Recent enrollments
    const recentEnrollments = await Enrollment.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate("student", "name email")
      .populate("course", "title price");

    // Popular courses (by enrollment count)
    const popularCourses = await Course.find({ status: "published" })
      .sort({ enrollmentCount: -1 })
      .limit(5)
      .select("title enrollmentCount rating image");

    res.json({
      stats: {
        totalStudents,
        totalCourses,
        activeStudents: activeStudents.length,
        revenue: totalStudents * 49, // placeholder revenue calc
      },
      recentEnrollments: recentEnrollments.map((e) => ({
        id: e._id,
        name: e.student?.name || "Unknown",
        email: e.student?.email || "",
        course: e.course?.title || "Unknown",
        date: formatTimeAgo(e.createdAt),
        price: `$${e.course?.price || 49}`,
      })),
      popularCourses,
    });
  } catch (err) {
    console.error("ADMIN STATS ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

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
