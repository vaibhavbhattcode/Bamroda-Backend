// models/BlogCategory.js
const mongoose = require("mongoose");

const blogCategorySchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
});

module.exports = mongoose.model("BlogCategory", blogCategorySchema);
