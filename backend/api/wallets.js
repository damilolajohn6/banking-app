const express = require("express");
const router = express.Router();
const WalletController = require("../controllers/walletController");

router.post("/", WalletController.createWallet);
router.get("/:userId/balance", WalletController.getBalance);

module.exports = router;
