const path=require('path');
const { StatusCodes } = require('http-status-codes')
const {User,Group,Post,Comment,Reaction,Relationship}=require(path.join(__dirname,'..','models'));
const {Op,Sequelize } = require('sequelize');


const search=async(req,res)=>
{
    let SearchResults=0;
    if(!req.query.text)
        return res.status(StatusCodes.OK).json({"msg":`${SearchResults} Search Results Found !!`});
    
    const users=await User.findAll({
        where:{
            username:{
                [Op.like]:`%${req.query.text}%`
            },
        },
        attributes: ['id','username', 'picturePath','state']
    });
    const groups=await Group.findAll({
        where:{
        [Op.or]:[
            {
                groupName: 
                { 
                    [Op.like]: `%${req.query.text}%` 
                }
            },
            {
                groupDescription: { 
                    [Op.like]: `%${req.query.text}%`
                }
            } 
        ]}
    });
    const uniqueUsersId = new Set();
    uniqueUsersId.add(req.user.id);
    const friends=await Relationship.findAll({
        where:{
            [Op.or]: [
                {
                    firstUserId:req.user.id,
                    state:"friends"
                },
                {
                    secondUserId:req.user.id,
                    state:"friends"
                }
            ] 
        },
        attributes:['firstUserId','secondUserId'],
    });
    friends.forEach((friend) => {
        uniqueUsersId.add(friend.firstUserId);
        uniqueUsersId.add(friend.secondUserId);
    });
    let idArr=[...uniqueUsersId];
    const posts=await Post.findAll({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']    
            },
            {
                model: Comment,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model: User,
                    attributes:['id','username','picturePath']
                }
            },
            {
                model:Reaction,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model:User,
                    attributes:['id','username','picturePath'],
                }
            }
        ],
        where:{
            text: { 
                [Op.like]: `%${req.query.text}%`,
            },
            userId:idArr.map((id)=>id), 
            state:"public"
        },
        attributes:{
            include: [
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM comments WHERE comments.postId = post.id)'), 'commentsCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="like")'), 'likesCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="dislike")'), 'dislikesCount'
                ]
            ],
            exclude:['UserId']
        }
    });
    
    if(users){
        SearchResults+=users.length;
    }
    if(groups){
        SearchResults+=groups.length;
    }
    if(posts){
        SearchResults+=posts.length;
    }
    res.status(StatusCodes.OK).json({
        "msg":`${SearchResults} Search Results Found !!`,
        users:users,
        groups:groups,
        posts:posts
    });
};

const news=async(req,res)=>
{
    const uniqueUsersId = new Set();
    uniqueUsersId.add(req.user.id);
    const friends=await Relationship.findAll({
        where:{
            [Op.or]: [
                {
                    firstUserId:req.user.id,
                    state:"friends"
                },
                {
                    secondUserId:req.user.id,
                    state:"friends"
                }
            ] 
        },
        attributes:['firstUserId','secondUserId'],
    });
    friends.forEach((friend) => {
        uniqueUsersId.add(friend.firstUserId);
        uniqueUsersId.add(friend.secondUserId);
    });
    let idArr=[...uniqueUsersId];
    const posts=await Post.findAll({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']    
            },
            {
                model: Comment,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model: User,
                    attributes:['id','username','picturePath']
                }
            },
            {
                model:Reaction,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model:User,
                    attributes:['id','username','picturePath'],
                }
            }
        ],
        where:{
            userId:idArr.map((id)=>id),
            state:"public"
        },
        attributes:{
            include: [
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM comments WHERE comments.postId = post.id)'), 'commentsCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="like")'), 'likesCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="dislike")'), 'dislikesCount'
                ]
            ],
            exclude:['UserId']
        },
        order: [
            ['updatedAt', 'DESC'],
        ],
    });
    res.status(StatusCodes.OK).json({posts:posts});
}

const homeController={
    search,
    news
}


module.exports=homeController;
