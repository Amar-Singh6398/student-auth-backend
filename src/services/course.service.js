const Course = require("../models/Course");

const getAllCourses = async (filters = {}) => {
  return await Course.find(filters);
};

const getCourseById = async (courseId) => {
  return await Course.findById(courseId);
};

const createCourse = async (courseData) => {
  const course = new Course(courseData);
  return await course.save();
};

const updateCourse = async (courseId, updateData) => {
  return await Course.findByIdAndUpdate(courseId, updateData, { new: true });
};

const deleteCourse = async (courseId) => {
  return await Course.findByIdAndDelete(courseId);
};

module.exports = {
  getAllCourses,
  getCourseById,
  createCourse,
  updateCourse,
  deleteCourse
};
