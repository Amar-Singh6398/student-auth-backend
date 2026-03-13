const authService = require("../services/auth.service");

// REGISTER
exports.register = async (req, res) => {
  try {
    const result = await authService.register(req.body);
    res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
};

// LOGIN
exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await authService.login(email, password);
    res.status(200).json(result);
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
};

// GET PROFILE
exports.getProfile = async (req, res) => {
  try {
    res.status(200).json({
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role
      }
    });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ADMIN: GET ALL STUDENTS
exports.getStudents = async (req, res) => {
  try {
    const students = await authService.getAllStudents();
    res.json(students);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ADMIN: DELETE USER
exports.deleteUser = async (req, res) => {
  try {
    await authService.deleteUser(req.params.id);
    res.json({ msg: "User removed" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

// ADMIN: UPDATE USER
exports.updateUser = async (req, res) => {
  try {
    const user = await authService.updateUser(req.params.id, req.body);
    res.json(user);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};
