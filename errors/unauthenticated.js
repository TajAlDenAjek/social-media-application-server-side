const path=require('path');
const { StatusCodes } = require('http-status-codes');
const CustomAPIError = require(path.join(__dirname,'custom-api'));

class UnauthenticatedError extends CustomAPIError
{
  constructor(message) 
  {
    super(message);
    this.statusCode = StatusCodes.UNAUTHORIZED;
  }
}

module.exports = UnauthenticatedError;
