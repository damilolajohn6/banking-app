const Wallet = require("../models/wallet");
const Transaction = require("../models/transaction");

// Create a new wallet for a user
exports.createWallet = async (req, res) => {
  try {
    const { user } = req.body;
    const wallet = await Wallet.create({ user });
    return res.status(201).json(wallet);
  } catch (error) {
    return res.status(500).json({ error: "Error creating wallet" });
  }
};

// Update a wallet's balance (e.g., for deposit or withdrawal)
exports.updateWallet = async (req, res) => {
  try {
    const { walletId } = req.params;
    const { amount, type } = req.body;

    const wallet = await Wallet.findById(walletId);
    if (!wallet) {
      return res.status(404).json({ error: "Wallet not found" });
    }

    if (type === "credit") {
      wallet.balance += amount;
    } else if (type === "debit") {
      if (wallet.balance < amount) {
        return res.status(400).json({ error: "Insufficient balance" });
      }
      wallet.balance -= amount;
    }

    await wallet.save();

    // Create a transaction record
    const transaction = new Transaction({
      wallet: wallet._id,
      amount,
      type,
    });
    await transaction.save();

    return res.status(200).json(wallet);
  } catch (error) {
    return res.status(500).json({ error: "Error updating wallet" });
  }
};

// Get wallet details for a user
exports.getWalletDetails = async (req, res) => {
  try {
    const { walletId } = req.params;
    const wallet = await Wallet.findById(walletId);
    if (!wallet) {
      return res.status(404).json({ error: "Wallet not found" });
    }
    return res.status(200).json(wallet);
  } catch (error) {
    return res.status(500).json({ error: "Error fetching wallet details" });
  }
};

// Transfer funds from one wallet to another
exports.transferFunds = async (req, res) => {
  try {
    const { senderWalletId, receiverWalletId, amount } = req.body;

    const senderWallet = await Wallet.findById(senderWalletId);
    const receiverWallet = await Wallet.findById(receiverWalletId);

    if (!senderWallet || !receiverWallet) {
      return res.status(404).json({ error: "Wallet not found" });
    }

    if (senderWallet.balance < amount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    senderWallet.balance -= amount;
    receiverWallet.balance += amount;

    await senderWallet.save();
    await receiverWallet.save();

    // Create transaction records for both wallets
    const senderTransaction = new Transaction({
      wallet: senderWallet._id,
      amount,
      type: "debit",
    });
    const receiverTransaction = new Transaction({
      wallet: receiverWallet._id,
      amount,
      type: "credit",
    });
    await senderTransaction.save();
    await receiverTransaction.save();

    return res.status(200).json({ message: "Funds transferred successfully" });
  } catch (error) {
    return res.status(500).json({ error: "Error transferring funds" });
  }
};

// Get a list of transactions for a wallet
exports.getTransactions = async (req, res) => {
  try {
    const { walletId } = req.params;
    const transactions = await Transaction.find({ wallet: walletId });
    return res.status(200).json(transactions);
  } catch (error) {
    return res.status(500).json({ error: "Error fetching transactions" });
  }
};
