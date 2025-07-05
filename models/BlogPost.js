// models/BlogPost.js
const mongoose = require("mongoose");

const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  coverImage: { type: String, required: true },
  content: { type: String, required: true },
  images: [{ type: String }],
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BlogCategory",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("BlogPost", blogPostSchema);
