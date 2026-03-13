const mongoose = require("mongoose");
const dotenv = require("dotenv");
const Course = require("./src/models/Course");
const User = require("./src/models/User");
const Enrollment = require("./src/models/Enrollment");

dotenv.config();

const courses = [
  {
    title: "Mastering React & Next.js",
    description: "Learn Next.js App Router, RSC, and more.",
    instructor: "Alex Rivera",
    image: "https://images.unsplash.com/photo-1633356122544-f134324a6cee?q=80&w=400&auto=format&fit=crop",
    category: "Development",
    tech: ["React", "Next.js", "Tailwind"],
    price: 49,
    rating: 4.8,
    status: "published",
    modules: [
      {
        title: "Introduction",
        lessons: [
          { title: "What is Next.js?", duration: "5:30", type: "video" },
          { title: "Project Structure", duration: "10:15", type: "video" }
        ]
      }
    ]
  },
  {
    title: "Node.js Backend Architecture",
    description: "Scalable backend systems with Node.",
    instructor: "Michael Ross",
    image: "https://images.unsplash.com/photo-1504639725590-34d0984388bd?q=80&w=400&auto=format&fit=crop",
    category: "Backend",
    tech: ["Node.js", "Express", "MongoDB"],
    price: 99,
    rating: 4.9,
    status: "published",
    modules: [
      {
        title: "Express Basics",
        lessons: [
          { title: "Middleware Deep Dive", duration: "15:00", type: "video" }
        ]
      }
    ]
  }
];

const seedDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to DB...");

    // Clear existing data (optional)
    await Course.deleteMany({});
    // ✅ Create Default Admin if not exists
    let admin = await User.findOne({ email: "admin@lms.com" });
    if (!admin) {
      admin = await User.create({
        name: "Admin User",
        email: "admin@lms.com",
        password: "password123",
        role: "admin"
      });
      console.log("Admin account created: admin@lms.com / password123");
    }

    // ✅ Create Default Student if not exists
    let student = await User.findOne({ email: "student@lms.com" });
    if (!student) {
      student = await User.create({
        name: "John Doe",
        email: "student@lms.com",
        password: "password123",
        role: "student"
      });
      console.log("Student account created: student@lms.com / password123");
    }

    const createdCourses = await Course.insertMany(courses);
    console.log("Courses seeded:", createdCourses.length);

    // Optional: Auto-enroll the test student into the courses for testing
    if (student) {
      console.log("Enrolling student:", student.email);
      for (const course of createdCourses) {
        await Enrollment.create({
          student: student._id,
          course: course._id,
          progress: 30, // Starting progress for UI demo
          lessonsCompleted: 1
        });
        course.enrollmentCount += 1;
        await course.save();
      }
      console.log("Enrollment complete.");
    }

    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

seedDB();
