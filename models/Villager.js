// models/Villager.js
const mongoose = require("mongoose");

const villagerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "UserProfile",
    required: true,
  },
  fullName: { type: String, required: true },
});

module.exports = mongoose.model("Villager", villagerSchema);
