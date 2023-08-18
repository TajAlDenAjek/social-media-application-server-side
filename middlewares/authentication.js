const path=require('path');
const {User}=require(path.join(__dirname,'..','models'));
const jwt = require('jsonwebtoken');
const { UnauthenticatedError } = require(path.join(__dirname,'..','errors'));

const auth = async (req, res, next) =>
{
    // check header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer'))
    {
        throw new UnauthenticatedError('Authentication invalid');
    }
    const accessToken = authHeader.split(' ')[1];
    try
    {
        const payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
        req.user = { id: payload.id, username: payload.username };
        let refreshToken=await User.findOne({where:{id:payload.id},attributes:['refreshToken']});
        refreshToken=refreshToken.dataValues.refreshToken;
        if(refreshToken===null||refreshToken!==accessToken)
            throw new UnauthenticatedError('Authentication invalid');
        next()
    } catch (error)
    {
        throw new UnauthenticatedError('Authentication invalid');
    }
}

module.exports=auth;
