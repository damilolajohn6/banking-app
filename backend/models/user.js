const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  // Additional KYC fields
  full_name: { type: String, required: true },
  date_of_birth: { type: Date, required: true },
  address: { type: String, required: true },
  phone_number: { type: Number, required: true },
  // Verification status
  email_verified: { type: Boolean, default: false },
  verified_at: { type: Date },
});

module.exports = mongoose.model("User", userSchema);
