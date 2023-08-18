const createComment = {
    "tags": [
        "Group Comment"
    ],
    "summary": "Create Comment",
    "operationId": "CreateComment",
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
        "201": {
            "description": "Created",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "createdAt": "2023-08-08T15:50:59.292Z",
                                    "updatedAt": "2023-08-08T15:50:59.294Z",
                                    "id": 4,
                                    "userId": 2,
                                    "postId": "5",
                                    "text": "comment"
                                }
                            }
                        ]
                    },
                    "example": {
                        "createdAt": "2023-08-08T15:50:59.292Z",
                        "updatedAt": "2023-08-08T15:50:59.294Z",
                        "id": 4,
                        "userId": 2,
                        "postId": "5",
                        "text": "comment"
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
                                    "msg": "failed",
                                    "errors": {
                                        "text": [
                                            "The text field is required."
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "text": [
                                "The text field is required."
                            ]
                        }
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

const editComment = {
    "tags": [
        "Group Comment"
    ],
    "summary": "Edit Comment",
    "operationId": "EditComment",
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
            "name": "commentId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the comment Id"
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
                                "text": "editing.."
                            }
                        }
                    ]
                },
                "example": {
                    "text": "editing.."
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
                                    "id": 3,
                                    "text": "editing..",
                                    "createdAt": "2023-08-04T13:07:37.000Z",
                                    "updatedAt": "2023-08-08T16:12:56.000Z",
                                    "userId": 2,
                                    "postId": 5
                                }
                            }
                        ]
                    },
                    "example": {
                        "id": 3,
                        "text": "editing..",
                        "createdAt": "2023-08-04T13:07:37.000Z",
                        "updatedAt": "2023-08-08T16:12:56.000Z",
                        "userId": 2,
                        "postId": 5
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
                                        "commentId": [
                                            "comment ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "commentId": [
                                "comment ont found"
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

const getComment = {
    "tags": [
        "Group Comment"
    ],
    "summary": "get Comment",
    "operationId": "getComment",
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
            "name": "commentId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the comment Id"
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
                                    "id": 4,
                                    "text": "comment",
                                    "createdAt": "2023-08-08T15:50:59.000Z",
                                    "updatedAt": "2023-08-08T15:50:59.000Z",
                                    "userId": 2,
                                    "postId": 5,
                                    "User": {
                                        "id": 2,
                                        "username": "potatUser",
                                        "picturePath": "image-1691430498994.png"
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "id": 4,
                        "text": "comment",
                        "createdAt": "2023-08-08T15:50:59.000Z",
                        "updatedAt": "2023-08-08T15:50:59.000Z",
                        "userId": 2,
                        "postId": 5,
                        "User": {
                            "id": 2,
                            "username": "potatUser",
                            "picturePath": "image-1691430498994.png"
                        }
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
                                        "commentId": [
                                            "comment ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "commentId": [
                                "comment ont found"
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

const deleteComment = {
    "tags": [
        "Group Comment"
    ],
    "summary": "Deleting Comment",
    "operationId": "DeletingComment",
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
            "name": "commentId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the comment Id"
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
                                    "msg": "comment has been deleted"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "comment has been deleted"
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
                                        "commentId": [
                                            "comment ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "commentId": [
                                "comment ont found"
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

const allCommentsOnPost = {
    "tags": [
        "Group Comment"
    ],
    "summary": "All Post's Comments",
    "operationId": "AllPost'sComments",
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
                        "type": "array",
                        "description": "",
                        "example": [
                            {
                                "id": 3,
                                "text": "editing..",
                                "createdAt": "2023-08-04T13:07:37.000Z",
                                "updatedAt": "2023-08-08T16:12:56.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 4,
                                "text": "comment",
                                "createdAt": "2023-08-08T15:50:59.000Z",
                                "updatedAt": "2023-08-08T15:50:59.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 5,
                                "text": "comment",
                                "createdAt": "2023-08-08T15:51:16.000Z",
                                "updatedAt": "2023-08-08T15:51:16.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 9,
                                "text": null,
                                "createdAt": "2023-08-08T15:53:36.000Z",
                                "updatedAt": "2023-08-08T15:53:36.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 10,
                                "text": null,
                                "createdAt": "2023-08-08T15:54:42.000Z",
                                "updatedAt": "2023-08-08T15:54:42.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            }
                        ]
                    },
                    "example": [
                        {
                            "id": 3,
                            "text": "editing..",
                            "createdAt": "2023-08-04T13:07:37.000Z",
                            "updatedAt": "2023-08-08T16:12:56.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 4,
                            "text": "comment",
                            "createdAt": "2023-08-08T15:50:59.000Z",
                            "updatedAt": "2023-08-08T15:50:59.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 5,
                            "text": "comment",
                            "createdAt": "2023-08-08T15:51:16.000Z",
                            "updatedAt": "2023-08-08T15:51:16.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 9,
                            "text": null,
                            "createdAt": "2023-08-08T15:53:36.000Z",
                            "updatedAt": "2023-08-08T15:53:36.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 10,
                            "text": null,
                            "createdAt": "2023-08-08T15:54:42.000Z",
                            "updatedAt": "2023-08-08T15:54:42.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        }
                    ]
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


const groupComment = {
    createComment,
    editComment,
    getComment,
    deleteComment,
    allCommentsOnPost
}


module.exports = groupComment;