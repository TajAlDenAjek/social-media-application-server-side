const path=require('path');
const reg_login_logout=require(path.join(__dirname,'docs','reg_login_logout'));
const user=require(path.join(__dirname,'docs','user'));
const post=require(path.join(__dirname,'docs','post'));
const comment=require(path.join(__dirname,'docs','comment'));
const reaction=require(path.join(__dirname,'docs','reaction'));
const relationship=require(path.join(__dirname,'docs','relationship'));
const home=require(path.join(__dirname,'docs','home'));
const chat=require(path.join(__dirname,'docs','chat'));
const group=require(path.join(__dirname,'docs','group'));
const groupPost=require(path.join(__dirname,'docs','groupPost'));
const groupComment=require(path.join(__dirname,'docs','groupComment'));
const groupReaction=require(path.join(__dirname,'docs','groupReaction'));
const images=require(path.join(__dirname,'docs','images'));


const swaggerDocument=
{
    openapi:"3.0.0",
    info:{
        title:"Social Media Application Api",
        version:"0.8",
        description:"Documentation of the api .."
    },
    servers:[
        {
            url:String(process.env.SERVER_SIDE_URL),
            description:"local dev server"
        }
    ],
    paths:{
        "/api/auth/register":{
            post:reg_login_logout.register
        },
        "/api/auth/login":{
            post:reg_login_logout.login
        },
        "/api/auth/logout":{
            get:reg_login_logout.logout
        },
        "/api/auth/refresh":{
            get:reg_login_logout.refresh
        },
        "/api/home/search{?text=queryString}":{
            get:home.search
        },
        "/api/home/news":{
            get:home.news
        },
        "/api/user/profile/{id}":{
            get:user.getOneUserProfile,
            patch:user.updateProfileById,
            delete:user.deleteUserById
        },
        "/api/post/create":{
            post:post.createPost
        },
        "/api/post/edit/{id}":{
            patch:post.editPost,
        },
        "/api/post/delete/{id}":{
            delete:post.deletePost
        },
        "/api/post/{id}":{
            get:post.getPostById
        },
        "/api/post/all/{id}":{
            get:post.getAllPostsById
        },
        "/api/comment/add/{id}":{
            post:comment.createComment
        },
        "/api/comment/edit/{id}":{
            patch:comment.editComment
        },
        "/api/comment/delete/{id}":{
            delete:comment.deleteComment
        },
        "/api/comment/{id}":{
            get:comment.getCommentById
        },
        "/api/comment/all/{id}":{
            get:comment.getAllCommentsById
        },
        "/api/reaction/add/{id}":{
            post:reaction.createReaction
        },
        "/api/reaction/edit/{id}":{
            patch:reaction.editReaction
        },
        "/api/reaction/delete/{id}":{
            delete:reaction.deleteReaction
        },
        "/api/reaction/{id}":{
            get:reaction.getReactionById
        },
        "/api/reaction/all/{id}":{
            get:reaction.getAllReactionsById
        },
        "/api/relationship/sendFriendRequest/{id}":{
            post:relationship.createFriendRequest
        },
        "/api/relationship/mySentRequests":{
            get:relationship.getSentRequests
        },
        "/api/relationship/myReceivedRequests":{
            get:relationship.getReceivedRequests
        },
        "/api/relationship/request/{id}":{
            delete:relationship.deleteSentRequest
        },
        "/api/relationship/response/accept/{id}":{
            patch:relationship.acceptReceivedRequest
        },
        "/api/relationship/response/reject/{id}":{
            delete:relationship.rejectReceivedRequest
        },
        "/api/relationship/removeFriend/{id}":{
            delete:relationship.removeFriend
        },
        "/api/relationship/myFriends":{
            get:relationship.getMyFriends
        },
        "/api/relationship/blockAFriend/{id}":{
            patch:relationship.blockAFriend
        },
        "/api/relationship/unblockAUser/{id}":{
            patch:relationship.unBlockAUser
        },
        "/api/relationship/myBlockedList":{
            get:relationship.getBlockedList
        },
        "/api/relationship/whoBlockedMeList":{
            get:relationship.getListOfPersonsWhoBlockedMe
        },
        "/api/chat/messages/{id}":{
            get:chat.getMessages
        },
        "/api/group/":{
            post:group.createGroup
        },
        "/api/group/{id}":{
            delete:group.deleteGroup,
            patch:group.editGroup,
            get:group.getGroup
        },
        "/api/group/my":{
            get:group.userGroups
        },
        "/api/group/{id}/join":{
            post:group.createJoinRequest,
            get:group.getJoinRequests
        },
        "/api/group/{id}/members":{
            get:group.getMembers
        },
        "/api/group/{groupId}/modifyRole/{userId}":{
            post:group.modifyRole
        },
        "/api/group/{groupId}/post":{
            get:groupPost.getPosts,
            post:groupPost.createPost
        },
        "/api/group/{groupId}/post/{postId}":{
            get:groupPost.getSinglePost,
            patch:groupPost.editPost,
            delete:groupPost.deletePost
        },
        "/api/group/{groupId}/comment/{postId}":{
            post:groupComment.createComment
        },
        "/api/group/{groupId}/comment/{commentId}":{
            patch:groupComment.editComment,
            get:groupComment.getComment,
            delete:groupComment.deleteComment
        },
        "/api/group/{groupId}/comment/all/{postId}":{
            get:groupComment.allCommentsOnPost
        },
        "/api/group/{groupId}/reaction/{postId}":{
            post:groupReaction.createReaction
        },
        "/api/group/{groupId}/reaction/{reactionId}":{
            get:groupReaction.getReaction,
            delete:groupReaction.deleteReaction,
            patch:groupReaction.editReaction
        },
        "/api/group/{groupId}/reaction/all/{postId}":{
            get:groupReaction.allReactionsOnPost
        },
        "/api/images/profile/{userId}":{
            get:images.profile
        },
        "/api/images/group/{groupId}":{
            get:images.group
        },
        "/api/images/post/{postId}":{
            get:images.post
        },
        "/api/images/groupPost/{postId}":{
            get:images.groupPost
        },
        "/public/images/{imageNameWithType}":{
            get:images.static
        }
    }
}


module.exports=swaggerDocument;