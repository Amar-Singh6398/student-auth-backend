const mongoose = require("mongoose");

const LessonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  type: { type: String, enum: ["video", "doc"], default: "video" },
  videoUrl: { type: String, default: "" },
  duration: { type: String, default: "" },
  locked: { type: Boolean, default: false },
});

const ModuleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  unlocked: { type: Boolean, default: true },
  lessons: [LessonSchema],
});

const CourseSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    instructor: { type: String, default: "Staff" },
    image: { type: String, default: "" },
    category: { type: String, default: "General" },
    tech: [{ type: String }],
    price: { type: Number, default: 0 },
    rating: { type: Number, default: 0 },
    status: { type: String, enum: ["published", "draft"], default: "published" },
    modules: [ModuleSchema],
    totalLessons: { type: Number, default: 0 },
    enrollmentCount: { type: Number, default: 0 },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true }
);

module.exports = mongoose.model("Course", CourseSchema);
