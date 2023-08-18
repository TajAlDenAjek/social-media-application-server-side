const path=require('path');
const whitelist=require(path.join(__dirname,'..','config','whitelist'));

const credentials=(req,res,next)=>
{
    const origin=req.headers.origin;
    if(whitelist.includes(origin))
    {
        res.header('Access-Control-Allow-Credentials',true);
    }
    next();
}
module.exports=credentials;