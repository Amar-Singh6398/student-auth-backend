const mongoose = require("mongoose");

const QuestionSchema = new mongoose.Schema({
  question: { type: String, required: true },
  options: [{ type: String }],
  correct: { type: Number, required: true }, // index of the correct option
});

const QuizSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    course: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
    timeLimit: { type: Number, default: 15 }, // in minutes
    difficulty: { type: String, enum: ["Beginner", "Intermediate", "Advanced"], default: "Beginner" },
    questions: [QuestionSchema],
    passingScore: { type: Number, default: 80 }, // percentage
  },
  { timestamps: true }
);

const QuizAttemptSchema = new mongoose.Schema(
  {
    student: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    quiz: { type: mongoose.Schema.Types.ObjectId, ref: "Quiz", required: true },
    answers: [{ type: Number }],
    score: { type: Number, default: 0 }, // percentage
    passed: { type: Boolean, default: false },
    completedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const Quiz = mongoose.model("Quiz", QuizSchema);
const QuizAttempt = mongoose.model("QuizAttempt", QuizAttemptSchema);

module.exports = { Quiz, QuizAttempt };
