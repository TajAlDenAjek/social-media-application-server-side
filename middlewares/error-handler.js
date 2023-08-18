const path =require('path');
const { StatusCodes } = require('http-status-codes');
const {logEvents}=require(path.join(__dirname,'logEvents.js'));
const CustomAPIError=require(path.join(__dirname,'..','errors'));


const errorHandlerMiddleware = (err, req, res, next) =>
{
  // console.log(err.stack);
  logEvents(`${err.name}: ${err.message}`,'errLog.txt');
  let customError=
  {
    // set default
    statusCode: err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR,
    msg: err.message || 'Something went wrong try again later',
  }
  if (err.name === 'ValidationError')
  {
    customError.msg = Object.values(err.errors).map((item) => item.message).join(',');
    customError.statusCode = StatusCodes.BAD_REQUEST;
  }
  // add special errors here 
  return res.status(customError.statusCode).json({ msg: customError.msg });
}


module.exports = errorHandlerMiddleware;
