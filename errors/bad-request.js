const path=require('path');
const { StatusCodes } = require('http-status-codes');
const CustomAPIError = require(path.join(__dirname,'custom-api'));

class BadRequestError extends CustomAPIError
{
  constructor(message)
  {
    super(message);
    this.statusCode = StatusCodes.BAD_REQUEST;
  }
}

module.exports = BadRequestError;
