const createFriendRequest={
    tags:["Relationships"],
    description:`create friend request by the id of the user</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        201:{
            description:"CREATED",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "request sent successfully",
                            "relationship": {
                              "createdAt": "2023-07-31T11:56:05.556Z",
                              "updatedAt": "2023-07-31T11:56:05.556Z",
                              "id": 14,
                              "firstUserId": 5,
                              "secondUserId":6,
                              "state": "pending"
                            }
                        }
                    }
                }
            }
        },
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "user": [
                              "User not found"
                            ]
                        }
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "No self loops in the friends system ,The given ID is the same as yours",
                            ]
                        }
                    }
                }
            }
        },  
        409:{
            description:"Conflict",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "relationship": [
                                "You have already sent a request to this user.",
                                "This user has sent you a request, Check received requests.",
                                "You are already friends.",
                                "You blocked this user.",
                                "This user has blocked you.",
                                "there is already a relationship."
                            ]
                        }
                    }
                }
            }
        },       
    }
}





const getSentRequests={
    tags:["Relationships"],
    description:`get sent requests for the current logged in user </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                              "requestRecevier": {
                                "id": 5,
                                "username": "User3",
                                "picturePath": null
                              },
                              "id": 13,
                              "firstUserId": 2,
                              "secondUserId": 5,
                              "state": "pending",
                              "createdAt": "2023-07-30T17:03:57.000Z",
                              "updatedAt": "2023-07-31T06:19:49.000Z"
                            }
                        ]
                    }
                }
            }
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },       
    }
}


const getReceivedRequests={
    tags:["Relationships"],
    description:`get received requests for the current logged in user </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                              "requestSender": {
                                "id": 2,
                                "username": "updatedUsername",
                                "picturePath": "image-1690691170494.PNG"
                              },
                              "id": 13,
                              "firstUserId": 2,
                              "secondUserId": 5,
                              "state": "received",
                              "createdAt": "2023-07-30T17:03:57.000Z",
                              "updatedAt": "2023-07-31T06:19:49.000Z"
                            }
                        ]
                    }
                }
            }
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },       
    }
}



const deleteSentRequest={
    tags:["Relationships"],
    description:`delete sent request by the id of the reqeust</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "relationship": [
                              "Relationship not found"
                            ],
                            "msg": "request has been deleted"
                        }
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "msg": "You are not a part of the relation",
                            },
                            {
                                "msg": "You are not the sender of the request"
                            }
                        ]
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "The request is not pending or recevied , you are friends or blocked "
                            ]
                        }
                    }
                }
            }
        },       
    }
}


const acceptReceivedRequest={
    tags:["Relationships"],
    description:`accept received request by the id of the request</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "relationship": [
                                  "Relationship not found"
                                ],
                            },
                            {
                                "msg": "request accepted successfully .. you are friends now !!",
                                "relationship": {
                                  "id": 16,
                                  "firstUserId": 2,
                                  "secondUserId": 5,
                                  "state": "friends",
                                  "createdAt": "2023-07-31T15:39:21.000Z",
                                  "updatedAt": "2023-07-31T15:53:00.000Z"
                                }
                            }
                        ]
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "msg": "You are not a part of the relation",
                            },
                            {
                                "msg": "You are not the receiver of the request"
                            }
                        ]
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "The request is not pending or recevied , you are friends or blocked "
                            ]
                        }
                    }
                }
            }
        },       
    }
}

const rejectReceivedRequest={
    tags:["Relationships"],
    description:`delete received request by the id of the reqeust</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "relationship": [
                              "Relationship not found"
                            ],
                            "msg": "request has been deleted"
                        }
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "msg": "You are not a part of the relation",
                            },
                            {
                                "msg": "You are not the receiver of the request"
                            }
                        ]
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "The request is not pending or recevied , you are friends or blocked "
                            ]
                        }
                    }
                }
            }
        },       
    }
}



const removeFriend={
    tags:["Relationships"],
    description:`remove friend by the id </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "user": [
                              "User not found"
                            ],
                            "msg": "friend has been removed"
                        }
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "This is user is not your friend !!"
                        }
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "No self loops in the friends system ,The given ID is the same as yours",
                            ]
                        }
                    }
                }
            }
        },       
    }
}


const getMyFriends={
    tags:["Relationships"],
    description:`get friends for the current logged in user </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                              "friend": {
                                "id": 6,
                                "username": "User3",
                                "picturePath": null
                              },
                              "id": 15,
                              "firstUserId": 6,
                              "secondUserId": 5,
                              "state": "friends",
                              "createdAt": "2023-07-31T12:05:28.000Z",
                              "updatedAt": "2023-07-31T12:10:50.000Z"
                            },
                            {
                              "friend": {
                                "id": 2,
                                "username": "updatedUsername",
                                "picturePath": "image-1690691170494.PNG"
                              },
                              "id": 16,
                              "firstUserId": 2,
                              "secondUserId": 5,
                              "state": "friends",
                              "createdAt": "2023-07-31T15:39:21.000Z",
                              "updatedAt": "2023-07-31T15:53:00.000Z"
                            }
                        ]
                    }
                }
            }
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },       
    }
}


const blockAFriend={
    tags:["Relationships"],
    description:`block friend by the id </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "user": [
                                  "User not found"
                                ],
                            },
                            {
                                "msg": "friend blocked successfully .. !!",
                                "relationship": {
                                  "id": 15,
                                  "firstUserId": 5,
                                  "secondUserId": 6,
                                  "state": "blocked",
                                  "createdAt": "2023-07-31T12:05:28.000Z",
                                  "updatedAt": "2023-07-31T16:57:51.000Z"
                                }
                            }
                        ]
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "This is user is not your friend !!"
                        }
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "No self loops in the friends system ,The given ID is the same as yours",
                            ]
                        }
                    }
                }
            }
        },       
    }
}


const unBlockAUser={
    tags:["Relationships"],
    description:`unblock user you blocked by the id </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "id",
          "in": "query",
          "type": "integer",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "user": [
                                  "User not found"
                                ],
                            },
                            {
                                "msg": "unblocked the user successfully .. you are friends now !!",
                                "relationship": {
                                  "id": 15,
                                  "firstUserId": 5,
                                  "secondUserId": 6,
                                  "state": "friends",
                                  "createdAt": "2023-07-31T12:05:28.000Z",
                                  "updatedAt": "2023-07-31T17:10:14.000Z"
                                }
                            }
                        ]
                    }
                }
            } 
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "You can't unblock someone who blocked you !!"
                        }
                    }
                }
            }
        },
        400:{
            description:"Bad Request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": [
                              "The id must be a number."
                            ],
                            "relationship": [
                                "No self loops in the friends system ,The given ID is the same as yours",
                                "there is no blocked relationship here"
                            ]
                        }
                    }
                }
            }
        },       
    }
}

const getBlockedList={
    tags:["Relationships"],
    description:`get the user blocked list </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            [
                                {
                                  "blockedUser": {
                                    "id": 6,
                                    "username": "User3",
                                    "picturePath": null
                                  },
                                  "id": 15,
                                  "firstUserId": 5,
                                  "secondUserId": 6,
                                  "state": "blocked",
                                  "createdAt": "2023-07-31T12:05:28.000Z",
                                  "updatedAt": "2023-07-31T17:13:45.000Z"
                                }
                            ]
                        ]
                    }
                }
            }
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },       
    }
}

const getListOfPersonsWhoBlockedMe={
    tags:["Relationships"],
    description:`get the list of persons who blocked you </br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            [
                                {
                                  "userBlockedMe": {
                                    "id": 5,
                                    "username": "User3",
                                    "picturePath": null
                                  },
                                  "id": 15,
                                  "firstUserId": 5,
                                  "secondUserId": 6,
                                  "state": "blocked",
                                  "createdAt": "2023-07-31T12:05:28.000Z",
                                  "updatedAt": "2023-07-31T17:13:45.000Z"
                                }
                            ]
                        ]
                    }
                }
            }
        },
        401:{
            description:"Unauthorized",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "Authentication invalid"
                        }
                    }
                }
            }
        },       
    }
}
const relationship=
{
    createFriendRequest,
    getSentRequests,
    getReceivedRequests,
    deleteSentRequest,
    acceptReceivedRequest,
    rejectReceivedRequest,
    removeFriend,
    getMyFriends,
    blockAFriend,
    unBlockAUser,
    getBlockedList,
    getListOfPersonsWhoBlockedMe
}


module.exports=relationship;