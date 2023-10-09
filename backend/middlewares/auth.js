const jwt = require("jsonwebtoken");
const { APIError } = require("../utils/errorHandler");

const JWT_SECRET = process.env.JWT_SECRET;

module.exports = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    const error = new APIError(
      401,
      "Unauthorized",
      "Authorization header missing"
    );
    return next(error);
  }

  try {
    const [tokenType, tokenValue] = token.split(" ");

    if (tokenType !== "Bearer") {
      const error = new APIError(401, "Unauthorized", "Invalid token type");
      return next(error);
    }

    const decoded = jwt.verify(tokenValue, JWT_SECRET);

    if (Date.now() >= decoded.exp * 1000) {
      const error = new APIError(401, "Unauthorized", "Token has expired");
      return next(error);
    }

    req.userId = decoded.userId;
    next();
  } catch (error) {
    const customError = new APIError(401, "Unauthorized", "Invalid token");
    return next(customError);
  }
};
