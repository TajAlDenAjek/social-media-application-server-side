const createReaction={
    tags:["Reactions"],
    description:`create reaction for a post giving the post id</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    requestBody:{  
        required:true,
        content:{
            "application/json":{
                schema:{
                    type:"Object",
                    example:[
                        {
                            "state": "dislike"
                        },
                        {
                            "state":"like"
                        }
                    ]
                }
            }
        },
    },
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
                            "post": [
                              "post not found"
                            ]
                        }
                    }
                }
            }
        },
        201:{
            description:"CREATED",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "createdAt": "2023-07-18T11:11:59.607Z",
                            "updatedAt": "2023-07-18T11:11:59.611Z",
                            "id": 4,
                            "userId": 1,
                            "postId": "9",
                            "state": "dislike"
                        }
                    }
                }
            }
        },
        400:{
            description:"bad request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "id": [
                                    "The id must be a number."
                                ]
                            },
                            {
                                "state": [
                                  "The selected state is invalid.",
                                  "The state field is required."
                                ]
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
                            "msg":"You can only see/interact your posts or your friends posts or your groups posts"
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
                            "reaction": [
                              "you have already reacted to this post"
                            ]
                        }
                    }
                }
            }
        },
    }
}



const editReaction={
    tags:["Reactions"],
    description:`edit reaction  giving the reaction id</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    requestBody:{  
        required:true,
        content:{
            "application/json":{
                schema:{
                    type:"Object",
                    example:[
                        {
                            "state": "dislike"
                        },
                        {
                            "state":"like"
                        }
                    ]
                }
            }
        },
    },
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
                                "id": 5,
                                "state": "like",
                                "createdAt": "2023-07-18T11:18:30.000Z",
                                "updatedAt": "2023-07-20T10:42:59.000Z",
                                "userId": 1,
                                "postId": 10
                            },
                            {
                                "reaction": [
                                    "Reaction not found"
                                ]    
                            }
                        ]
                    }
                }
            }
        },
        400:{
            description:"bad request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "id": [
                                    "The id must be a number."
                                ]
                            },
                            {
                                "state": [
                                  "The selected state is invalid.",
                                  "The state field is required."
                                ]
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
                                "msg": "You can only modify your reactions",
                            },
                            {
                                "msg":"You can't update your reaction on post of user who is not your friend"
                            }                         
                        ]
                    }
                }
            }
        },
    }
}


const deleteReaction={
    tags:["Reactions"],
    description:`delete reaction  giving the reaction id</br >
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
                                "msg": "reaction has been deleted"
                            },
                            {
                                "reaction": [
                                    "Reaction not found"
                                ]    
                            }
                        ]
                    }
                }
            }
        },
        400:{
            description:"bad request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "id": [
                                    "The id must be a number."
                                ]
                            },
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
                            "msg": "You can only modify your reactions",
                        }
                    }
                }
            }
        },
    }
}


const getReactionById={
    tags:["Reactions"],
    description:`get One reaction By Id of the reaction</br >
    you must be authorized </br>
    <h3> Note : send token in bearer </h3>
    `,
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
                            "oneReaction":{
                                "id": 5,
                                "state": "dislike",
                                "createdAt": "2023-07-18T11:18:30.000Z",
                                "updatedAt": "2023-07-20T11:13:30.000Z",
                                "userId": 1,
                                "postId": 10,
                                "User": {
                                  "username": "potatoCodeforces",
                                  "picturePath": null
                                }
                            },
                            "reaction": [
                                "Reaction not found"
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
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "You can only see your reactions or your friends reactions or your groups reactions"
                        }
                    }
                }
            }
        },
        400:{
            description:"bad request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "id": [
                                    "The id must be a number."
                                ]
                            }, 
                        ]
                    }
                }
            }
        }
    }
}






const getAllReactionsById={
    tags:["Reactions"],
    description:`get all reactions of user By user id</br >
    you must be authorized </br>
    <h3> Note : send token in bearer </h3>
    `,
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
                            "ListOfReactions":[
                                {
                                  "id": 5,
                                  "state": "dislike",
                                  "createdAt": "2023-07-18T11:18:30.000Z",
                                  "updatedAt": "2023-07-20T11:13:30.000Z",
                                  "userId": 1,
                                  "postId": 10,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                },
                                {
                                  "id": 8,
                                  "state": "like",
                                  "createdAt": "2023-07-20T11:36:43.000Z",
                                  "updatedAt": "2023-07-20T11:36:43.000Z",
                                  "userId": 1,
                                  "postId": 9,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                }
                            ],
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
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "You can only see your reactions or your friends reactions or your groups reactions"
                        }
                    }
                }
            }
        },
        400:{
            description:"bad request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "id": [
                                    "The id must be a number."
                                ]
                            }, 
                        ]
                    }
                }
            }
        }
    }
}

const reaction={
    createReaction,
    editReaction,
    deleteReaction,
    getReactionById,
    getAllReactionsById
}


module.exports=reaction;