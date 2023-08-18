const path=require('path');
const CustomAPIError = require(path.join(__dirname,'custom-api'));
const UnauthenticatedError = require(path.join(__dirname,'unauthenticated'));
const NotFoundError = require(path.join(__dirname,'not-found'));
const BadRequestError = require(path.join(__dirname,'bad-request'));
const unauthorized = require(path.join(__dirname,'unauthorized'));


module.exports =
{
  CustomAPIError,
  UnauthenticatedError,
  NotFoundError,
  BadRequestError,
  unauthorized,
}
