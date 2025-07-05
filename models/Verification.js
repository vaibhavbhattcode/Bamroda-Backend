// models/Verification.js
const mongoose = require("mongoose");

const verificationSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 }, // 5 minutes expiration
});

module.exports = mongoose.model("Verification", verificationSchema);
