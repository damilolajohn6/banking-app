const mongoose = require("mongoose");

const transactionSchema = new mongoose.Schema({
  senderWalletId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Wallet",
    required: true,
  },
  receiverWalletId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Wallet",
    required: true,
  },
  amount: { type: Number, required: true },
  status: {
    type: String,
    enum: ["success", "pending", "failed"],
    default: "pending",
  },
  type: { type: String, enum: ["debit", "credit"], required: true },
  charges: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Transaction", transactionSchema);
