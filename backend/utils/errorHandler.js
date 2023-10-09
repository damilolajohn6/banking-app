class APIError extends Error {
  constructor(status, message, details) {
    super();
    this.status = status;
    this.message = message;
    this.details = details;
  }
}

module.exports = {
  APIError,
};
