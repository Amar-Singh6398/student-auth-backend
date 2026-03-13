const User = require("../models/User");
const generateToken = require("../utils/generateToken");

const register = async (userData) => {
  const { name, email, password, role } = userData;
  let user = await User.findOne({ email });
  if (user) throw new Error("User already exists");

  user = new User({ name, email, password, role });
  await user.save();

  return {
    token: generateToken(user),
    user: { id: user._id, name: user.name, email: user.email, role: user.role }
  };
};

const login = async (email, password) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error("Invalid credentials");

  const isMatch = await user.matchPassword(password);
  if (!isMatch) throw new Error("Invalid credentials");

  return {
    token: generateToken(user),
    user: { id: user._id, name: user.name, email: user.email, role: user.role }
  };
};

const getAllStudents = async () => {
  return await User.find({ role: "student" }).select("-password");
};

const deleteUser = async (userId) => {
  return await User.findByIdAndDelete(userId);
};

const updateUser = async (userId, updateData) => {
  return await User.findByIdAndUpdate(userId, updateData, { new: true }).select("-password");
};

module.exports = {
  register,
  login,
  getAllStudents,
  deleteUser,
  updateUser
};
