const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { APIError } = require('../utils/errorHandler');
require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "1h" }); // Token expires in 1 hour
};


// User registration
router.post("/register", async (req, res, next) => {
  try {
    const {
      username,
      password,
      email,
      full_name,
      date_of_birth,
      address,
      phone_number,
    } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the saltRounds

    // Create a new user with the hashed password
    const user = new User({
      username,
      password: hashedPassword, // Save the hashed password
      email,
      full_name,
      date_of_birth,
      address,
      phone_number,
    });

    // Save the user to the database
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

    if (!user) {
      console.log("User not found");
      throw new APIError(401, "Invalid login credentials");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    // console.log("Is password valid:", isPasswordValid);

    if (!isPasswordValid) {
      console.log("Invalid password");
      throw new APIError(401, "Invalid login credentials");
    }

    const token = generateToken(user._id);
    res.json({ token });
  } catch (error) {
    console.error("Login Error:", error);
    next(new APIError(401, error.message));
  }
});


module.exports = router;
