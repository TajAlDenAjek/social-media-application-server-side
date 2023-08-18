const profile = {
    "tags": [
        "Images"
    ],
    "summary": "Profile",
    "operationId": "Profile",
    "parameters": [
        {
            "in": "path",
            "name": "userId",
            "schema": {
                "type": "integer"
            },
            "required": true
        }
    ],
    "responses": {
        "404": {
            "description": "Not Found",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "failed",
                                    "errors": {
                                        "userId": [
                                            "user not found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "userId": [
                                "user not found"
                            ]
                        }
                    }
                }
            }
        }
    },
    "deprecated": false,
    "security": [
        {
            "bearer": []
        }
    ],
}

const group = {
    "tags": [
        "Images"
    ],
    "summary": "group",
    "operationId": "group",
    "parameters": [
        {
            "in": "path",
            "name": "groupId",
            "schema": {
                "type": "integer"
            },
            "required": true
        }
    ],
    "responses": {
        "404": {
            "description": "Not Found",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "failed",
                                    "errors": {
                                        "groupId": [
                                            "group not found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "groupId": [
                                "group not found"
                            ]
                        }
                    }
                }
            }
        }
    },
    "deprecated": false,
    "security": [
        {
            "bearer": []
        }
    ],
}

const post = {
    "tags": [
        "Images"
    ],
    "summary": "post",
    "operationId": "post",
    "parameters": [
        {
            "in": "path",
            "name": "postId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the post Id"
        }
    ],
    "responses": {
        "404": {
            "description": "Not Found",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "failed",
                                    "errors": {
                                        "postId": [
                                            "post ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "postId": [
                                "post ont found"
                            ]
                        }
                    }
                }
            }
        }
    },
    "deprecated": false,
    "security": [
        {
            "bearer": []
        }
    ],
}

const groupPost = {
    "tags": [
        "Images"
    ],
    "summary": "group post",
    "operationId": "grouppost",
    "parameters": [
        {
            "in": "path",
            "name": "postId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the post Id"
        }
    ],
    "responses": {
        "404": {
            "description": "Not Found",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "failed",
                                    "errors": {
                                        "postId": [
                                            "post not found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "postId": [
                                "post not found"
                            ]
                        }
                    }
                }
            }
        }
    },
    "deprecated": false,
    "security": [
        {
            "bearer": []
        }
    ],
}

const static={
    tags:["Images"],
    description:`static path for images by the (picturePath)</br >
    you must be authorized </br>
    <h3> Note : send token in bearer </h3>
    `,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
          "name": "picturePath",
          "in": "query",
          "type": "string",
          "required": true
        }
    ],
    responses:{
        200:{
            description:"OK",
            content:{
                "file":{
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
        404:{
            description:" 404 Not Found",
            content:{
                "application/json":{
                    schema:{
                        type:"Object",
                        example:[
                            {
                                "html":"<h1>404 <br> Route does not exist</br></h1>"
                            }, 
                        ]
                    }
                }
            }
        }
    }
}



const images = {
    profile,
    group,
    post,
    groupPost,
    static
}


module.exports = images;