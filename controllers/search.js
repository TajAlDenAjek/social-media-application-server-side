const path = require('path') ;
const {Group , GroupUser , User , Post , GroupPost , Relationship , sequelize ,Comment }= require(path.join(__dirname , '..' , 'models'  )) ;
const {QueryTypes , Op } = require('sequelize');


const searchForUsers = async (req ,res )=>{
    let users = await User.findAll({where:{username:{[Op.like]: `%${req.body.query}%`}} , attributes: ['id','username', 'picturePath']  });
    return res.json({msg:'success' , users}) ;
}
const searchForGroups = async (req, res )=>{
    let groups = await Group.findAll({where:{
        [Op.or] : [
            {
                groupName: 
                { 
                    [Op.like]: `%${req.body.query}%` 
                }
            },
            {
                groupDescription: { 
                    [Op.like]: `%${req.body.query}%`
                }
            } 
        ]
    }}) ;
    return res.json({msg:'success' , groups}) ;
}
const searchForPosts = async (req ,res )=>{
    // maybe vuln to sql injection 
    let posts = await sequelize.query(`
    SELECT posts.id , userId , text , picture, username ,picturePath, posts.updatedAt , posts.createdAt 
    from posts , relationships , users  WHERE (
    relationships.firstUserId = posts.userId 
    OR relationships.secondUserId = posts.userId 
    )
    AND users.id = posts.userId 
    AND posts.text like "%${req.body.query}%" ORDER BY createdAt`
    , {type:QueryTypes.SELECT , model:Post , mapToModel:true });
    return res.json({msg:'success' , posts }) ;
}
const searchForComments = async (req ,res )=>{
    // maybe vuln to sql injection
    
    let comments = await sequelize.query(`
        SELECT userId , text , username , postId , comments.createdAt , comments.updatedAt from comments , relationships , users  WHERE (
            comments.userId = relationships.firstUserId 
            OR 
            comments.userId = relationships.secondUserId
        )
        AND users.id = comments.userId
        AND comments.text like "%${req.body.query}%" ORDER BY createdAt
    `, {type:QueryTypes.SELECT , model: Comment, mapToModel:true }) ;
    return res.json({msg:'success' , comments} ) ;
}




const serachController = {
    searchForGroups , 
    searchForUsers,
    searchForPosts,
    searchForComments
};
module.exports= serachController;