// basic packages
require('dotenv').config();
require('express-async-errors');
const path=require('path');
const express=require('express');
const app=express();
const corsOptions=require(path.join(__dirname,'config','corsOptions'));
const db=require(path.join(__dirname,'models','index.js'));

// third-party middlewares
const cookieParser = require('cookie-parser');

// built-in middlewares 
const errorHandlerMiddleware = require(path.join(__dirname,'middlewares','error-handler'));
const {logger}=require(path.join(__dirname,'middlewares','logEvents'));
const notFound=require(path.join(__dirname,'middlewares','notFound.js'));
const credentials=require(path.join(__dirname,'middlewares','credentials.js'));


// security packages 
const helmet = require('helmet');
const cors = require('cors');
const xss = require('xss-clean');
const rateLimiter = require('express-rate-limit');
const authenticated=require(path.join(__dirname,'middlewares','authentication.js'));

// import mainRouter
const mainRouter=require(path.join(__dirname,'routes'));

// socket io stuff
const server = require('http').createServer(app);
const initializeSocket=require(path.join(__dirname,'socket'));

// using middlewares and actual routes
app.set('trust proxy', 1);
// app.use(
//     rateLimiter(
//     {
//         windowMs: 15 * 60 * 1000, // 15 minutes
//         max: 100, // limit each IP to 100 requests per windowMs
//     })
// );
app.use(express.json()); 
app.use(cookieParser());
app.use(helmet());
app.use(cors(corsOptions));
app.use(xss());

app.use('/api/public/images',authenticated,express.static(path.join(__dirname,'public','images')));
app.use(logger);
app.use(credentials);


app.use('/',mainRouter);


app.use(notFound);
app.use(errorHandlerMiddleware);

// setting up the server and connecting to the database
const PORT=process.env.SERVER_PORT||3500;

db.sequelize.sync().then(()=>{
    console.log('Connnected to the dataBase');
    server.listen(PORT,()=>console.log(`Server is running on port ${PORT} ... `));
    initializeSocket(server);

}).catch((error)=>{
    console.log(error);
});

