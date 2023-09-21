const register={
    tags:["register login && logout"],
    description:`create a user </br >
    you need to pass in request body </br>
    <ul>
        <li><b>username</br></b></li>
        <li><b>valid unique email</br></b></li>
        <li><b>and password with with minimum length of 8 chars and max length of 20</b></b></li>
    </ul>
    <h3> Note : users are distinct by email </h3>
    `,
    requestBody:{  
        required:true,
        content:{
            "application/json":{
                schema:{
                    type:"Object",
                    example:{
                        username:"potato",
                        email:"potato@email.com",
                        password:"potatoPassword"
                    }
                }
            }
        },
    },
    responses:{
        201:{
            description:"created",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "msg": "created successfully",
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
                        example:{
                            "username": [
                                "The username field is required."
                              ],
                              "email": [
                                "The email field is required.",
                                "Email is already in use !", 
                                "The email format is invalid."
                              ],
                              "password": [
                                "The password field is required.",
                                "The password must be at least 8 characters.",
                                "The password may not be greater than 20 characters."
                            ]
                        }
                    }
                }
            }
        }
    }
}


const login={
    tags:["register login && logout"],
    description:`login route for a registered email</br >
    you need to pass in request body </br>
    <ul>
        <li><b>valid email</br></b></li>
        <li><b>and a password</b></b></li>
    </ul>
    <h3> Note : Keep your token safe you need to use it && you will recieve a cookie </h3>
    `,
    requestBody:{
        required:true,
        content:{
            "application/json":{
                schema:{
                    type:"Object",
                    example:{
                        email:"potato@email.com",
                        password:"potatoPassword"
                    }
                }
            }
        },
    },
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "user": {
                                "id": 10,
                                "username": "potato"
                            },
                            "token": "the token string"
                        }
                    }
                },
            }
        },
        400:{
            description:"bad request",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                              "email": [
                                "The email field is required.",
                                "The email format is invalid."
                              ],
                              "password": [
                                "The password field is required.",
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
                            "email": [
                                "Invalid Credentials no such email"
                            ],
                            "password": [
                                "Invalid Credentials Wrong Password"
                            ]
                        }
                    }
                }
            }
        }
    }
}

const logout={
    tags:["register login && logout"],
    description:`logout route for the current logged in email</br >
    you must be authorized </br>
    <h3> Note : send token in bearer </h3>
    `,
    security: [{
        bearerAuth: []
    }],
    responses:{
        204:{
            description:"No content",
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
        }
    }
}

const refresh={
    tags:["register login && logout"],
    description:`refresh token route when access token expired request this route to give a new life</br >
    you need to pass in header a cookie name jwt and the refresh token you recieved when login
    " Cookie jwt=refresh token"
    <h3> Note : Keep your token safe you need to use it </h3>
    `,
    requestBody:{
        required:true,
        content:{
            "application/json":{
                schema:{
                    type:"Object",
                    example:{
                        email:"potato@email.com",
                        password:"potatoPassword"
                    }
                }
            }
        },
    },
    responses:{
        200:{
            description:"OK",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:{
                            "user": {
                                "id": 10,
                                "username": "potato"
                            },
                            "token": "the token string"
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
                    }
                }
            }
        }
    }
}


const reg_login_logout=
{
    register,
    login,
    logout,
    refresh
}


module.exports=reg_login_logout;