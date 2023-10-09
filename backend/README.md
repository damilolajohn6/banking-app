# Wallet API

The Wallet API is a Node.js and Express-based RESTful API that allows users to create wallets, manage wallet balances, transfer funds between wallets, and view transaction history. This project uses MongoDB for data storage and JWT (JSON Web Tokens) for authentication.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Contributing](#contributing)

## Features

- User registration and login.
- Wallet creation and balance management.
- Secure fund transfers between wallets with validation.
- Transaction history for each wallet.
- JWT-based authentication for secure API access.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Node.js and npm installed.
- MongoDB database accessible.

## Getting Started

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/damilolajohn6/wallet-api.git
   ```

2. Navigate to the project directory:

   ```bash
   cd wallet-api
   ```

3. Install dependencies:

   ```bash
   npm install
   ```

### Configuration

1. Set up your MongoDB connection in the `app.js` file by replacing the connection string:

   ```javascript
   mongoose.connect('mongodb+srv://damilolajohn622:*************@dailys.ukhegz8.mongodb.net/', { useNewUrlParser: true, useUnifiedTopology: true })
   ```

2. Configure your JWT secret key in the authentication routes (`routes/auth.js`):

   ```javascript
   const token = jwt.sign({ userId: user._id }, 'your_secret_key');
   ```

## API Endpoints

Here are the available API endpoints:

- **User Registration:** `/api/register` (POST)
  - Create a new user.

- **User Login:** `/api/login` (POST)
  - Authenticate and receive a JWT token.

- **Create Wallet:** `/api/wallet/create` (POST)
  - Create a wallet for the authenticated user.

- **Get Wallet Details:** `/api/wallet/details` (GET)
  - Retrieve wallet details for the authenticated user.

- **Update Wallet Balance:** `/api/wallet/update` (PUT)
  - Update the wallet balance for the authenticated user.

- **Transfer Funds:** `/api/transaction/transfer` (POST)
  - Transfer funds between two wallets.

- **Get Transaction History:** `/api/transaction/history` (GET)
  - Retrieve the transaction history for the authenticated user.

## Authentication

Authentication for this API is done using JWT (JSON Web Tokens). To access protected endpoints, include the JWT token in the `Authorization` header of your requests.

Example:

```bash
curl -X GET http://localhost:3000/api/wallet/details -H "Authorization: YOUR_JWT_TOKEN_HERE"
```

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please follow these guidelines:

1. Fork the project.
2. Create your feature branch.
3. Commit your changes .
4. Push to the branch .
5. Create a new Pull Request.


Feel free to customize this README to suit your project's specific needs. Providing clear and concise documentation is essential for your project's success and helps both developers and users understand how to use your Wallet-API.
