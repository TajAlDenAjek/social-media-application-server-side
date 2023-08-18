const path=require('path');
const { StatusCodes } = require('http-status-codes');
const CustomAPIError = require(path.join(__dirname,'custom-api'));

class NotFoundError extends CustomAPIError
{
  constructor(message)
  {
    super(message);
    this.statusCode = StatusCodes.NOT_FOUND;
  }
}

module.exports = NotFoundError;
