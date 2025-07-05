// models/UserProfile.js
const mongoose = require("mongoose");

const profileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  photo: { type: String },
  surname: { type: String, required: true },
  name: { type: String, required: true },
  fatherName: { type: String, required: true },
  dob: { type: Date, required: true },
  age: { type: Number, required: true },
  mobile: { type: String, required: true },
  address: { type: String, required: true },
  achievements: [
    {
      type: {
        type: String,
        enum: ["Academic", "Sports", "Professional", "Other"],
      },
      description: { type: String },
      year: { type: Number },
    },
  ],
  certificates: [{ type: String }],
});

module.exports = mongoose.model("UserProfile", profileSchema);
