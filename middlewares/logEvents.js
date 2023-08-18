const {format}=require('date-fns');
const {v5:uuid}=require('uuid');
const fs=require('fs');
const path=require('path');
const fsPromises=require('fs').promises;



const logEvents=async(message,logName)=>
{
    const dateTime=`${format(new Date(),'yyyy/MM/dd\tHH:mm:ss')}`;
    const logItem=`${dateTime}\t${uuid.DNS}\t${message}\n`;
    try
    {
        if(!fs.existsSync(path.join(__dirname,'..','logs')))
        {
            await fsPromises.mkdir(path.join(__dirname,'..','logs'));
        }
        await fsPromises.appendFile(path.join(__dirname,'..','logs',logName),logItem);
    }catch(e){
        console.log(e);
    }
}


const logger=(req,res,next)=>
{
    logEvents(`${req.method}\t${req.headers.origin}\t${req.url}`,'reqLog.txt');
    next();
}


module.exports={logger,logEvents};
