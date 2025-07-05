// models/GalleryCategory.js
const mongoose = require("mongoose");

const galleryCategorySchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
});

module.exports = mongoose.model("GalleryCategory", galleryCategorySchema);
