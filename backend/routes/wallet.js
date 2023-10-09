const express = require("express");
const router = express.Router();
const Wallet = require("../models/wallet");
const authMiddleware = require("../middlewares/auth");

// Create a wallet for the authenticated user
router.post("/create", authMiddleware, async (req, res) => {
  try {
    const wallet = new Wallet({ userId: req.userId });
    await wallet.save();
    res.status(201).json({ message: "Wallet created successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get wallet details for the authenticated user
router.get("/details", authMiddleware, async (req, res) => {
  try {
    const wallet = await Wallet.findOne({ userId: req.userId });
    res.json(wallet);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update wallet balance for the authenticated user
router.put("/update", authMiddleware, async (req, res) => {
  try {
    const { balance } = req.body;
    await Wallet.updateOne({ userId: req.userId }, { balance });
    res.json({ message: "Wallet balance updated successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
