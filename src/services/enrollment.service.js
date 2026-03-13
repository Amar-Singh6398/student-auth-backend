const Enrollment = require("../models/Enrollment");
const Course = require("../models/Course");

const enroll = async (studentId, courseId) => {
  const existing = await Enrollment.findOne({ student: studentId, course: courseId });
  if (existing) throw new Error("Already enrolled in this course");

  const enrollment = new Enrollment({
    student: studentId,
    course: courseId
  });

  await enrollment.save();
  
  // Update course enrollment count
  await Course.findByIdAndUpdate(courseId, { $inc: { enrollmentCount: 1 } });

  return enrollment;
};

const getStudentEnrollments = async (studentId) => {
  return await Enrollment.find({ student: studentId }).populate("course");
};

const updateProgress = async (studentId, courseId, lessonId) => {
  const enrollment = await Enrollment.findOne({ student: studentId, course: courseId });
  if (!enrollment) throw new Error("Enrollment not found");

  // Logic to mark lesson complete and update percentage
  // For simplicity, let's just update lastAccessed
  enrollment.lastAccessedAt = Date.now();
  await enrollment.save();
  return enrollment;
};

const getPlatformStats = async () => {
    // Basic stats for admin
    const enrollments = await Enrollment.find().populate("student", "name").populate("course", "title");
    return enrollments;
}

module.exports = {
  enroll,
  getStudentEnrollments,
  updateProgress,
  getPlatformStats
};
