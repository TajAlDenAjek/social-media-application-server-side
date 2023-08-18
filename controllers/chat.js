const path=require('path');
const { StatusCodes } = require('http-status-codes');
const {User,Relationship,Chat}=require(path.join(__dirname,'..','models'));
const { Op ,Sequelize} = require('sequelize');


const getMessages=async(req,res)=>
{
    let firstUserId=Number(req.user.id);
    let secondUserId=Number(req.params.id);
    const messages=await Chat.findAll({
        include:[
            {
                model: User,
                as:'senderUser',
                attributes: ['id','username', 'picturePath']   
            },
            {
                model: User,
                as:'reciverUser',
                attributes: ['id','username', 'picturePath']   
            }
        ],
        where:{
            [Op.or]: [
                {
                    senderUserId:firstUserId,
                    reciverUserId:secondUserId,
                },
                {
                    reciverUserId:firstUserId,
                    senderUserId:secondUserId,
                }
            ] 
        },
        order: [
            ['updatedAt', 'ASC'],
        ],
    });
    res.status(StatusCodes.OK).json({chat:messages});
}

const chatController={
    getMessages
}

module.exports=chatController;