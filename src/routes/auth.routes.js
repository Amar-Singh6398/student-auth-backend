const express = require("express");
const router = express.Router();

const { register, login, getProfile } = require("../controllers/auth.controller");
const {forgotPassword} = require("../controllers/forgot.password")
const {resetPassword} = require("../controllers/reset.password")

const { protect } = require("../middleware/auth.middleware");

router.post("/register", register);
router.post("/login", login);
router.get("/me", protect, getProfile); // <- THIS is the route


// 🔥 NEW ROUTES
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);


module.exports = router;
