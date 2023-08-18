const getPosts = {
    "tags": [
        "Group Post"
    ],
    "summary": "Get Posts",
    "operationId": "GetPosts",
    "parameters": [
        {
            "in": "path",
            "name": "groupId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the group Id"
        }
    ],
    "responses": {
        "200": {
            "description": "OK",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "posts": [
                                        {
                                            "postId": 5,
                                            "Post": {
                                                "id": 5,
                                                "text": "potato",
                                                "picture": null,
                                                "createdAt": "2023-08-04T12:46:53.000Z",
                                                "state": null,
                                                "updatedAt": "2023-08-04T12:46:53.000Z",
                                                "userId": 2,
                                                "UserId": 2,
                                                "User": {
                                                    "id": 2,
                                                    "username": "potatUser",
                                                    "picturePath": "image-1691430498994.png"
                                                },
                                                "Comments": [
                                                    {
                                                        "id": 3,
                                                        "text": "comment",
                                                        "createdAt": "2023-08-04T13:07:37.000Z",
                                                        "updatedAt": "2023-08-04T13:07:37.000Z",
                                                        "userId": 2,
                                                        "postId": 5,
                                                        "User": {
                                                            "id": 2,
                                                            "username": "potatUser",
                                                            "picturePath": "image-1691430498994.png"
                                                        }
                                                    }
                                                ],
                                                "Reactions": []
                                            }
                                        },
                                        {
                                            "postId": 2,
                                            "Post": {
                                                "id": 2,
                                                "text": null,
                                                "picture": null,
                                                "createdAt": "2023-08-03T22:09:14.000Z",
                                                "state": null,
                                                "updatedAt": "2023-08-03T22:09:14.000Z",
                                                "userId": 2,
                                                "UserId": 2,
                                                "User": {
                                                    "id": 2,
                                                    "username": "potatUser",
                                                    "picturePath": "image-1691430498994.png"
                                                },
                                                "Comments": [],
                                                "Reactions": []
                                            }
                                        },
                                        {
                                            "postId": 3,
                                            "Post": {
                                                "id": 3,
                                                "text": "potato",
                                                "picture": null,
                                                "createdAt": "2023-08-04T11:05:34.000Z",
                                                "state": null,
                                                "updatedAt": "2023-08-04T11:05:34.000Z",
                                                "userId": 2,
                                                "UserId": 2,
                                                "User": {
                                                    "id": 2,
                                                    "username": "potatUser",
                                                    "picturePath": "image-1691430498994.png"
                                                },
                                                "Comments": [],
                                                "Reactions": []
                                            }
                                        },
                                        {
                                            "postId": 6,
                                            "Post": {
                                                "id": 6,
                                                "text": null,
                                                "picture": null,
                                                "createdAt": "2023-08-08T13:53:26.000Z",
                                                "state": "private",
                                                "updatedAt": "2023-08-08T13:53:26.000Z",
                                                "userId": 2,
                                                "UserId": 2,
                                                "User": {
                                                    "id": 2,
                                                    "username": "potatUser",
                                                    "picturePath": "image-1691430498994.png"
                                                },
                                                "Comments": [],
                                                "Reactions": []
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "example": {
                        "posts": [
                            {
                                "postId": 5,
                                "Post": {
                                    "id": 5,
                                    "text": "potato",
                                    "picture": null,
                                    "createdAt": "2023-08-04T12:46:53.000Z",
                                    "state": null,
                                    "updatedAt": "2023-08-04T12:46:53.000Z",
                                    "userId": 2,
                                    "UserId": 2,
                                    "User": {
                                        "id": 2,
                                        "username": "potatUser",
                                        "picturePath": "image-1691430498994.png"
                                    },
                                    "Comments": [
                                        {
                                            "id": 3,
                                            "text": "comment",
                                            "createdAt": "2023-08-04T13:07:37.000Z",
                                            "updatedAt": "2023-08-04T13:07:37.000Z",
                                            "userId": 2,
                                            "postId": 5,
                                            "User": {
                                                "id": 2,
                                                "username": "potatUser",
                                                "picturePath": "image-1691430498994.png"
                                            }
                                        }
                                    ],
                                    "Reactions": []
                                }
                            },
                            {
                                "postId": 2,
                                "Post": {
                                    "id": 2,
                                    "text": null,
                                    "picture": null,
                                    "createdAt": "2023-08-03T22:09:14.000Z",
                                    "state": null,
                                    "updatedAt": "2023-08-03T22:09:14.000Z",
                                    "userId": 2,
                                    "UserId": 2,
                                    "User": {
                                        "id": 2,
                                        "username": "potatUser",
                                        "picturePath": "image-1691430498994.png"
                                    },
                                    "Comments": [],
                                    "Reactions": []
                                }
                            },
                            {
                                "postId": 3,
                                "Post": {
                                    "id": 3,
                                    "text": "potato",
                                    "picture": null,
                                    "createdAt": "2023-08-04T11:05:34.000Z",
                                    "state": null,
                                    "updatedAt": "2023-08-04T11:05:34.000Z",
                                    "userId": 2,
                                    "UserId": 2,
                                    "User": {
                                        "id": 2,
                                        "username": "potatUser",
                                        "picturePath": "image-1691430498994.png"
                                    },
                                    "Comments": [],
                                    "Reactions": []
                                }
                            },
                            {
                                "postId": 6,
                                "Post": {
                                    "id": 6,
                                    "text": null,
                                    "picture": null,
                                    "createdAt": "2023-08-08T13:53:26.000Z",
                                    "state": "private",
                                    "updatedAt": "2023-08-08T13:53:26.000Z",
                                    "userId": 2,
                                    "UserId": 2,
                                    "User": {
                                        "id": 2,
                                        "username": "potatUser",
                                        "picturePath": "image-1691430498994.png"
                                    },
                                    "Comments": [],
                                    "Reactions": []
                                }
                            }
                        ]
                    }
                }
            }
        },
        "400": {
            "description": "Bad Request",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Forbidden Operation Not allowed"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Forbidden Operation Not allowed"
                    }
                }
            }
        },
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

const createPost = {
    "tags": [
        "Group Post"
    ],
    "summary": "Create Post",
    "operationId": "CreatePost",
    "parameters": [
        {
            "in": "path",
            "name": "groupId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the group Id"
        }
    ],
    "requestBody": {
        "description": "",
        "content": {
            "text/plain": {
                "schema": {
                    "type": "object",
                    "example": {}
                },
                "example": {}
            }
        },
        "required": true
    },
    "responses": {
        "200": {
            "description": "OK",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Post created successfully",
                                    "post": {
                                        "createdAt": "2023-08-08T14:29:12.156Z",
                                        "updatedAt": "2023-08-08T14:29:12.159Z",
                                        "id": 7,
                                        "userId": 2,
                                        "text": "creating new post",
                                        "state": "private"
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Post created successfully",
                        "post": {
                            "createdAt": "2023-08-08T14:29:12.156Z",
                            "updatedAt": "2023-08-08T14:29:12.159Z",
                            "id": 7,
                            "userId": 2,
                            "text": "creating new post",
                            "state": "private"
                        }
                    }
                }
            }
        },
        "400": {
            "description": "Bad Request",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Forbidden Operation Not allowed"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Forbidden Operation Not allowed"
                    }
                }
            }
        },
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

const getSinglePost = {
    "tags": [
        "Group Post"
    ],
    "summary": "Get Post",
    "operationId": "GetPost",
    "parameters": [
        {
            "in": "path",
            "name": "groupId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the group Id"
        },
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
        "200": {
            "description": "OK",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "success",
                                    "post": {
                                        "id": 1,
                                        "text": "text for post",
                                        "picture": null,
                                        "createdAt": "2023-08-01T23:19:00.000Z",
                                        "state": "public",
                                        "updatedAt": "2023-08-01T23:19:00.000Z",
                                        "userId": 2,
                                        "commentsCount": 1,
                                        "likesCount": 0,
                                        "dislikesCount": 0,
                                        "User": {
                                            "id": 2,
                                            "username": "potatUser",
                                            "picturePath": "image-1691430498994.png"
                                        },
                                        "Comments": [
                                            {
                                                "id": 1,
                                                "text": "comment text",
                                                "createdAt": "2023-08-01T23:19:40.000Z",
                                                "updatedAt": "2023-08-01T23:19:40.000Z",
                                                "userId": 2,
                                                "postId": 1,
                                                "User": {
                                                    "id": 2,
                                                    "username": "potatUser",
                                                    "picturePath": "image-1691430498994.png"
                                                }
                                            }
                                        ],
                                        "Reactions": []
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "success",
                        "post": {
                            "id": 1,
                            "text": "text for post",
                            "picture": null,
                            "createdAt": "2023-08-01T23:19:00.000Z",
                            "state": "public",
                            "updatedAt": "2023-08-01T23:19:00.000Z",
                            "userId": 2,
                            "commentsCount": 1,
                            "likesCount": 0,
                            "dislikesCount": 0,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            },
                            "Comments": [
                                {
                                    "id": 1,
                                    "text": "comment text",
                                    "createdAt": "2023-08-01T23:19:40.000Z",
                                    "updatedAt": "2023-08-01T23:19:40.000Z",
                                    "userId": 2,
                                    "postId": 1,
                                    "User": {
                                        "id": 2,
                                        "username": "potatUser",
                                        "picturePath": "image-1691430498994.png"
                                    }
                                }
                            ],
                            "Reactions": []
                        }
                    }
                }
            }
        },
        "400": {
            "description": "Bad Request",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Forbidden Operation Not allowed"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Forbidden Operation Not allowed"
                    }
                }
            }
        },
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


const editPost = {
    "tags": [
        "Group Post"
    ],
    "summary": "Edit post",
    "operationId": "Editpost",
    "parameters": [
        {
            "in": "path",
            "name": "groupId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the group Id"
        },
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
    "requestBody": {
        "description": "",
        "content": {
            "application/json": {
                "schema": {
                    "allOf": [
                        {
                            "example": {
                                "text": "editing"
                            }
                        }
                    ]
                },
                "example": {
                    "text": "editing"
                }
            }
        },
        "required": true
    },
    "responses": {
        "200": {
            "description": "OK",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "post updated successfully"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "post updated successfully"
                    }
                }
            }
        },
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

const deletePost = {
    "tags": [
        "Group Post"
    ],
    "summary": "Delete Post",
    "operationId": "DeletePost",
    "parameters": [
        {
            "in": "path",
            "name": "groupId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the group Id"
        },
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
        "200": {
            "description": "OK",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "success"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "success"
                    }
                }
            }
        },
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
    getPosts,
    createPost,
    getSinglePost,
    editPost,
    deletePost
}

module.exports = groupPost;