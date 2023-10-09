const express = require("express");
const router = express.Router();
const TransactionController = require("../controllers/transactionController");

router.post("/", TransactionController.makeTransaction);

module.exports = router;
