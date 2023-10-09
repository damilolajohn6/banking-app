const Transaction = require('../models/transaction');
const Wallet = require('../models/wallet');
const { APIError } = require('../utils/errorHandler')

const getTransactionHistory = async (req, res, next) => {
  try {
    let transactions = [];

    const searchType = req.query.type;

    if (searchType) {
      transactions = transactions.filter(
        (transaction) => transaction.type === searchType
      );
    }

    res.status(200).json({ transactions });
  } catch (error) {
    next(new APIError(400, error.message));
  }
};


const transferFunds = async (req, res, next) => {
  try {
    const { senderWalletId, receiverWalletId, amount } = req.body;

    // Retrieve sender and receiver wallets
    const senderWallet = await Wallet.findById(senderWalletId);
    const receiverWallet = await Wallet.findById(receiverWalletId);

    if (!senderWallet || !receiverWallet) {
      throw new APIError(400, "Invalid sender or receiver wallet ID.");
    }

    if (senderWallet.balance < amount) {
      throw new APIError(400, "Insufficient funds in the sender wallet.");
    }

    // Create debit transaction for sender
    const debitTransaction = new Transaction({
      senderWalletId,
      receiverWalletId,
      amount,
      type: "debit",
      charges: 0,
      status: "success", // Assuming the transaction is successful
    });

    // Create credit transaction for receiver
    const creditTransaction = new Transaction({
      senderWalletId,
      receiverWalletId,
      amount,
      type: "credit",
      charges: 0,
      status: "success", // Assuming the transaction is successful
    });

    // Update sender's wallet balance and transaction count
    senderWallet.balance -= amount;
    senderWallet.transactionCount += 1;
    senderWallet.totalAmountSent += amount;

    // Update receiver's wallet balance and transaction count
    receiverWallet.balance += amount;
    receiverWallet.transactionCount += 1;
    receiverWallet.totalAmountReceived += amount;

    // Save transactions and update wallet details
    await debitTransaction.save();
    await creditTransaction.save();
    await senderWallet.save();
    await receiverWallet.save();

    res.status(200).json({ message: "Funds transferred successfully" });
  } catch (error) {
    next(new APIError(400, error.message));
  }
};

module.exports = {
  transferFunds,
  getTransactionHistory,
};
