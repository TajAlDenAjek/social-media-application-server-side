const createComment={
    tags:["Comments"],
    description:`create comment for a post giving the post id</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>
    <h3> Note 2: you can send data as raw json in body request </h3>`,
    security: [{
        bearerAuth: []
    }],
    requestBody:{  
        required:true,
        content:{
            "application/json":{
                schema:{
                    type:"Object",
                    example:{
                        "text":"comment text"
                    }
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
                            "createdAt": "2023-07-16T11:22:38.912Z",
                            "updatedAt": "2023-07-16T11:22:38.913Z",
                            "id": 12,
                            "userId": 1,
                            "postId": "9",
                            "text": "comment text",
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
                                "text": [
                                    "The text field is required."
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
                            "msg": "You can only see/(interact with )your posts or your friends posts or your groups posts"
                        }
                    }
                }
            }
        },
    }
}

const editComment={
    tags:["Comments"],
    description:`update comment by id</br >
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
                    example:{
                        "text":"updated text for a comment"
                    }
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
        },
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "id": 14,
                            "text": "updated text for a comment",
                            "createdAt": "2023-07-16T11:34:44.000Z",
                            "updatedAt": "2023-07-16T11:34:51.000Z",
                            "userId": 1,
                            "postId": 9,
                            "comment": [
                                "comment not found"
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
                        example:[
                            {
                                "msg": "You can only modify your comments",
                            },
                            {
                                "msg": "You can't update your comment on post of user who is not your friend"
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
                                "text": [
                                    "The text field is required."
                                ]
                            }
                        ]
                    }
                }
            }
        }
    }
}

const deleteComment={
    tags:["Comments"],
    description:`delete comment by id</br >
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
        },
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "comment has been deleted",
                            "comment": [
                                "comment not found"
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
                            "msg": "You can only modify your comments"
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

const getCommentById={
    tags:["Comments"],
    description:`get One comment By Id of the comment</br >
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
                            "oneComment":{
                                "id": 7,
                                "text": null,
                                "createdAt": "2023-07-16T10:52:24.000Z",
                                "updatedAt": "2023-07-16T10:52:24.000Z",
                                "userId": 4,
                                "postId": 9,
                                "User": {
                                  "username": "potatoCodeforces",
                                  "picturePath": null
                                }
                            },
                            "comment": [
                                "comment not found"
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
                            "msg": "You can only see your comments or your friends comments or your groups comments"
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

const getAllCommentsById={
    tags:["Comments"],
    description:`get all comments of user By user id</br >
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
                            "ListOfComments":[
                                {
                                  "id": 8,
                                  "text": "updated text for a comment",
                                  "createdAt": "2023-07-16T10:54:39.000Z",
                                  "updatedAt": "2023-07-16T11:01:20.000Z",
                                  "userId": 1,
                                  "postId": 9,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                },
                                {
                                  "id": 10,
                                  "text": "comment",
                                  "createdAt": "2023-07-16T11:22:11.000Z",
                                  "updatedAt": "2023-07-16T11:22:11.000Z",
                                  "userId": 1,
                                  "postId": 9,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                },
                                {
                                  "id": 11,
                                  "text": "updated text for a comment",
                                  "createdAt": "2023-07-16T11:22:19.000Z",
                                  "updatedAt": "2023-07-16T11:36:10.000Z",
                                  "userId": 1,
                                  "postId": 9,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                },
                                {
                                  "id": 12,
                                  "text": "comment text",
                                  "createdAt": "2023-07-16T11:22:38.000Z",
                                  "updatedAt": "2023-07-16T11:22:38.000Z",
                                  "userId": 1,
                                  "postId": 9,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                },
                                {
                                  "id": 13,
                                  "text": "updated text for a comment",
                                  "createdAt": "2023-07-16T11:24:31.000Z",
                                  "updatedAt": "2023-07-16T11:36:06.000Z",
                                  "userId": 1,
                                  "postId": 9,
                                  "User": {
                                    "username": "potatoCodeforces",
                                    "picturePath": null
                                  }
                                },
                                {
                                  "id": 15,
                                  "text": "comment text",
                                  "createdAt": "2023-07-18T08:21:56.000Z",
                                  "updatedAt": "2023-07-18T08:21:56.000Z",
                                  "userId": 1,
                                  "postId": 10,
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
                            "msg": "You can only see your comments or your friends comments or your groups comments"
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

const comment={
    createComment,
    editComment,
    deleteComment,
    getCommentById,
    getAllCommentsById
}


module.exports=comment;