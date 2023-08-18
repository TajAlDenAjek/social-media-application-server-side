const path=require('path');
const whitelist=require(path.join(__dirname,'whitelist'));
const {StatusCodes}=require('http-status-codes');
const { UnauthenticatedError } = require(path.join(__dirname,'..','errors','unauthenticated'));

const corsOptions=
{
    origin:(origin,callback)=>
    {
        if(whitelist.indexOf(origin)!==-1||origin==undefined)
        {
            callback(null,true);
        }
        else
        {
            callback(new UnauthenticatedError('Forbbiden by cross origin resource'));
        }
    },
    optionSuccessStatus:StatusCodes.OK
}

module.exports=corsOptions;