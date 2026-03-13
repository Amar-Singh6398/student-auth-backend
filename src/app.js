const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/auth.routes");
const courseRoutes = require("./routes/course.routes");
const dashboardRoutes = require("./routes/dashboard.routes");

const app = express();

// ✅ CORS setup for frontend + credentials
app.use(cors({
  origin: "http://localhost:3000", // <-- your frontend URL
  credentials: true                // <-- important for withCredentials
}));

// Body parser
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/courses", courseRoutes);
app.use("/api/dashboard", dashboardRoutes);

module.exports = app;
