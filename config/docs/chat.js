const getMessages={
    tags:["Chat"],
    description:`get messages of your friend by the id of your friend </br >
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
                                "chat": [
                                  {
                                    "id": 1,
                                    "message": "Hello second User How are you",
                                    "createdAt": "2023-08-02T00:00:00.000Z",
                                    "updatedAt": "2023-08-02T00:00:00.000Z",
                                    "senderUserId": 1,
                                    "reciverUserId": 2,
                                    "senderUser": {
                                      "id": 1,
                                      "username": "first",
                                      "picturePath": null
                                    },
                                    "reciverUser": {
                                      "id": 2,
                                      "username": "second",
                                      "picturePath": null
                                    }
                                  },
                                  {
                                    "id": 2,
                                    "message": "Hello first User I am fine",
                                    "createdAt": "2023-08-02T12:00:00.000Z",
                                    "updatedAt": "2023-08-02T12:00:00.000Z",
                                    "senderUserId": 2,
                                    "reciverUserId": 1,
                                    "senderUser": {
                                      "id": 2,
                                      "username": "second",
                                      "picturePath": null
                                    },
                                    "reciverUser": {
                                      "id": 1,
                                      "username": "first",
                                      "picturePath": null
                                    }
                                  }
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

const chat={
    getMessages
}


module.exports=chat;