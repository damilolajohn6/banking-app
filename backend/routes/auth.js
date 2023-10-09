const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { APIError } = require('../utils/errorHandler');
require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" }); // Token expires in 1 hour
};


// User registration
router.post("/register", async (req, res, next) => {
  try {
    const { username, password, email, full_name, date_of_birth, address, phone_number } = req.body;
    const user = new User({
      username,
      password,
      email,
      full_name,
      date_of_birth,
      address,
      phone_number,
    });
    await user.save();
    const token = generateToken(user._id);

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    next(new APIError(400, error.message));
  }
});

// User login
router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new APIError(401, "Invalid login credentials");
    }

    // Generate JWT token upon successful login
    const token = generateToken(user._id);

    res.json({ token });
  } catch (error) {
    next(new APIError(401, error.message));
  }
});

module.exports = router;
