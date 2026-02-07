const crypto = require("crypto");
const User = require("../models/User");
const sendEmail = require("../utils/sendEmail");

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const resetToken = crypto.randomBytes(32).toString("hex");

  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  user.resetPasswordToken = hashedToken;
  user.resetPasswordExpire = Date.now() + 15 * 60 * 1000;

  await user.save();

  // ✅ FIXED
  const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

  const message = `
Click the link below to reset your password:

${resetUrl}

This link expires in 15 minutes.
If you did not request this, ignore this email.
`;

  await sendEmail(user.email, "Reset Your Password", message);

  res.json({ message: "Reset link sent to email" });
};
