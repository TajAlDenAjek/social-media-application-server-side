const getOneUserProfile={
    tags:["Users"],
    description:`get profile information of user by id</br >
    you must be authorized logged in </br>
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
                        example:[
                            {
                                "id": 2,
                                "username": "potato",
                                "email": "potato@email.com",
                                "firstName": null,
                                "lastName": null,
                                "picturePath": null,
                                "gender": null,
                                "birthday": null,
                                "country": null,
                                "createdAt": "2023-06-15T07:17:39.000Z",
                                "updatedAt": "2023-06-15T07:17:39.000Z",
                                "state":["friends","not friends","pending"," "]
                            },{
                                "user": [
                                    "User not found"
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
        403:{
            description:"Forbidden",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "msg": "this user is blocked"
                            },
                        ]
                    }
                }
            }
        }
    }
}

const updateProfileById={
    tags:["Users"],
    description:`update the user info</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>
    <h3> Note 2: Don't send data as raw json you have to send it as form-data 
    key value give the picture field name 'image' and the rest of the data 'data' it's optional to send (single image ,json data ,both single image and json data) </h3>
    <h3> Note 3: If you updated the password you need to login again </h3>
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
        },
        {
            in: 'formData',
            name: 'data',
            type: 'application/json',
            description: 'JSON data to update make sure to give it the field name (data)',
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            
                            "username": "potatoUserName",
                            "password": "potatoNewPassword",
                            "firstName": "potatoFirstName",
                            "lastName": "potatoLastName",
                            "gender": "male",
                            "birthday": "2022-01-01",
                            "country": "potatoContury"       
                        }
                    }
                }
            }
        },
        {
            in: 'formData',
            name: 'image',
            type: 'file',
            description: 'Image to update make sure to give it the field name (image)',
            example: '{"image": "the picture you will upload"}',
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
                            "msg": "updated successfully",
                            "user":[
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
                            "msg": "You can only modify your account"
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
                                "password": [
                                    "The password must be at least 8 characters.",
                                    "The password may not be greater than 20 characters."
                                ]
                            },
                            {
                                "gender": [
                                    "The selected gender is invalid."
                                ]
                            },
                            {
                                "birthday": [
                                    "The birthday is not a valid date format."
                                ]
                            }
                        ]
                    }
                }
            }
        }
    }
}
const deleteUserById={
    tags:["Users"],
    description:`delete the user</br >
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
                            "msg": "account has been deleted",
                            "user":[
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
                            "msg": "You can only modify your account"
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

const user={
    getOneUserProfile,
    updateProfileById,
    deleteUserById
}


module.exports=user;