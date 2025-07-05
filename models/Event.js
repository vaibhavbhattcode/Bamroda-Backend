// models/Event.js
const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String },
    location: { type: String },
    date: { type: Date, required: true },
    image: { type: String }, // stores the filename of the uploaded image
  },
  { timestamps: true }
);

module.exports = mongoose.model("Event", eventSchema);
