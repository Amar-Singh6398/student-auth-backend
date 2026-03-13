const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema({
  name:{type:String, required:true },
  email: { type: String, required: true, unique: true },

  password: { type: String, required: true },

  role: { type: String, default: "student" },

  // ✅ ADD THESE TWO LINES
  resetPasswordToken: String,
  resetPasswordExpire: Date
});

// Hash password before save
UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

UserSchema.methods.matchPassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model("User", UserSchema);
