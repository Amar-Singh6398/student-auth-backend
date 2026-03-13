const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/auth.routes");
const courseRoutes = require("./routes/course.routes");
const dashboardRoutes = require("./routes/dashboard.routes");
const enrollmentRoutes = require("./routes/enrollment.routes");

const app = express();

// ✅ CORS setup for frontend + credentials
app.use(cors({
  origin: "http://localhost:3000", // <-- your frontend URL
  credentials: true                // <-- important for withCredentials
}));

// Body parser
app.use(express.json());

// Routes
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/courses", courseRoutes);
app.use("/api/v1/enrollments", enrollmentRoutes);
app.use("/api/v1/dashboard", dashboardRoutes);

module.exports = app;
