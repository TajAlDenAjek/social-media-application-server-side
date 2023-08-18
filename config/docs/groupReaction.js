const createReaction = {
    "tags": [
        "Group Reaction"
    ],
    "summary": "Create Reaction",
    "operationId": "CreateReaction",
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
                                "state": "dislike"
                            }
                        }
                    ]
                },
                "example": {
                    "state": "dislike"
                }
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
                                    "createdAt": "2023-08-08T16:24:35.906Z",
                                    "updatedAt": "2023-08-08T16:24:35.908Z",
                                    "id": 2,
                                    "userId": 2,
                                    "postId": "5"
                                }
                            }
                        ]
                    },
                    "example": {
                        "createdAt": "2023-08-08T16:24:35.906Z",
                        "updatedAt": "2023-08-08T16:24:35.908Z",
                        "id": 2,
                        "userId": 2,
                        "postId": "5"
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
        },
        "409": {
            "description": "Conflict",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "reaction": [
                                        "you have already reacted to this post"
                                    ]
                                }
                            }
                        ]
                    },
                    "example": {
                        "reaction": [
                            "you have already reacted to this post"
                        ]
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


const getReaction = {
    "tags": [
        "Group Reaction"
    ],
    "summary": "get Reaction",
    "operationId": "getReaction",
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
            "name": "reactionId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the reaction Id"
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
                                    "id": 2,
                                    "state": null,
                                    "createdAt": "2023-08-08T16:24:35.000Z",
                                    "updatedAt": "2023-08-08T16:24:35.000Z",
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
                        "id": 2,
                        "state": null,
                        "createdAt": "2023-08-08T16:24:35.000Z",
                        "updatedAt": "2023-08-08T16:24:35.000Z",
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
                                        "reactionId": [
                                            "reaction ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "reactionId": [
                                "reaction ont found"
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

const deleteReaction = {
    "tags": [
        "Group Reaction"
    ],
    "summary": "Delete Reaction",
    "operationId": "DeleteReaction",
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
            "name": "reactionId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the reaction Id"
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
                                    "msg": "reaction has been deleted"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "reaction has been deleted"
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
                                        "reactionId": [
                                            "reaction ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "reactionId": [
                                "reaction ont found"
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


const editReaction = {
    "tags": [
        "Group Reaction"
    ],
    "summary": "Edit Reaction",
    "operationId": "EditReaction",
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
            "name": "reactionId",
            "schema": {
                "type": "integer"
            },
            "required": true,
            "description": "the reaction Id"
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
                                "state": "dislike"
                            }
                        }
                    ]
                },
                "example": {
                    "state": "dislike"
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
                                    "id": 5,
                                    "state": "dislike",
                                    "createdAt": "2023-08-08T16:25:27.000Z",
                                    "updatedAt": "2023-08-08T17:42:15.000Z",
                                    "userId": 2,
                                    "postId": 5
                                }
                            }
                        ]
                    },
                    "example": {
                        "id": 5,
                        "state": "dislike",
                        "createdAt": "2023-08-08T16:25:27.000Z",
                        "updatedAt": "2023-08-08T17:42:15.000Z",
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
                                        "reactionId": [
                                            "reaction ont found"
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "reactionId": [
                                "reaction ont found"
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


const allReactionsOnPost = {
    "tags": [
        "Group Reaction"
    ],
    "summary": "get All Reaction",
    "operationId": "getAllReaction",
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
                                "id": 2,
                                "state": null,
                                "createdAt": "2023-08-08T16:24:35.000Z",
                                "updatedAt": "2023-08-08T16:24:35.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 3,
                                "state": null,
                                "createdAt": "2023-08-08T16:24:47.000Z",
                                "updatedAt": "2023-08-08T16:24:47.000Z",
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
                                "state": null,
                                "createdAt": "2023-08-08T16:25:21.000Z",
                                "updatedAt": "2023-08-08T16:25:21.000Z",
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
                                "state": "dislike",
                                "createdAt": "2023-08-08T16:25:27.000Z",
                                "updatedAt": "2023-08-08T17:42:15.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 6,
                                "state": null,
                                "createdAt": "2023-08-08T16:25:29.000Z",
                                "updatedAt": "2023-08-08T16:25:29.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 7,
                                "state": null,
                                "createdAt": "2023-08-08T16:25:30.000Z",
                                "updatedAt": "2023-08-08T16:25:30.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 8,
                                "state": null,
                                "createdAt": "2023-08-08T16:25:32.000Z",
                                "updatedAt": "2023-08-08T16:25:32.000Z",
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
                                "state": null,
                                "createdAt": "2023-08-08T16:25:33.000Z",
                                "updatedAt": "2023-08-08T16:25:33.000Z",
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
                                "state": null,
                                "createdAt": "2023-08-08T16:25:34.000Z",
                                "updatedAt": "2023-08-08T16:25:34.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 11,
                                "state": null,
                                "createdAt": "2023-08-08T16:25:36.000Z",
                                "updatedAt": "2023-08-08T16:25:36.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 12,
                                "state": null,
                                "createdAt": "2023-08-08T16:25:37.000Z",
                                "updatedAt": "2023-08-08T16:25:37.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 13,
                                "state": null,
                                "createdAt": "2023-08-08T16:25:38.000Z",
                                "updatedAt": "2023-08-08T16:25:38.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 14,
                                "state": "like",
                                "createdAt": "2023-08-08T16:25:50.000Z",
                                "updatedAt": "2023-08-08T16:25:50.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 15,
                                "state": "like",
                                "createdAt": "2023-08-08T16:25:53.000Z",
                                "updatedAt": "2023-08-08T16:25:53.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 16,
                                "state": "like",
                                "createdAt": "2023-08-08T16:25:54.000Z",
                                "updatedAt": "2023-08-08T16:25:54.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 17,
                                "state": "like",
                                "createdAt": "2023-08-08T16:25:56.000Z",
                                "updatedAt": "2023-08-08T16:25:56.000Z",
                                "userId": 2,
                                "postId": 5,
                                "User": {
                                    "id": 2,
                                    "username": "potatUser",
                                    "picturePath": "image-1691430498994.png"
                                }
                            },
                            {
                                "id": 18,
                                "state": "dislike",
                                "createdAt": "2023-08-08T16:26:01.000Z",
                                "updatedAt": "2023-08-08T16:26:01.000Z",
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
                            "id": 2,
                            "state": null,
                            "createdAt": "2023-08-08T16:24:35.000Z",
                            "updatedAt": "2023-08-08T16:24:35.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 3,
                            "state": null,
                            "createdAt": "2023-08-08T16:24:47.000Z",
                            "updatedAt": "2023-08-08T16:24:47.000Z",
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
                            "state": null,
                            "createdAt": "2023-08-08T16:25:21.000Z",
                            "updatedAt": "2023-08-08T16:25:21.000Z",
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
                            "state": "dislike",
                            "createdAt": "2023-08-08T16:25:27.000Z",
                            "updatedAt": "2023-08-08T17:42:15.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 6,
                            "state": null,
                            "createdAt": "2023-08-08T16:25:29.000Z",
                            "updatedAt": "2023-08-08T16:25:29.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 7,
                            "state": null,
                            "createdAt": "2023-08-08T16:25:30.000Z",
                            "updatedAt": "2023-08-08T16:25:30.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 8,
                            "state": null,
                            "createdAt": "2023-08-08T16:25:32.000Z",
                            "updatedAt": "2023-08-08T16:25:32.000Z",
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
                            "state": null,
                            "createdAt": "2023-08-08T16:25:33.000Z",
                            "updatedAt": "2023-08-08T16:25:33.000Z",
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
                            "state": null,
                            "createdAt": "2023-08-08T16:25:34.000Z",
                            "updatedAt": "2023-08-08T16:25:34.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 11,
                            "state": null,
                            "createdAt": "2023-08-08T16:25:36.000Z",
                            "updatedAt": "2023-08-08T16:25:36.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 12,
                            "state": null,
                            "createdAt": "2023-08-08T16:25:37.000Z",
                            "updatedAt": "2023-08-08T16:25:37.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 13,
                            "state": null,
                            "createdAt": "2023-08-08T16:25:38.000Z",
                            "updatedAt": "2023-08-08T16:25:38.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 14,
                            "state": "like",
                            "createdAt": "2023-08-08T16:25:50.000Z",
                            "updatedAt": "2023-08-08T16:25:50.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 15,
                            "state": "like",
                            "createdAt": "2023-08-08T16:25:53.000Z",
                            "updatedAt": "2023-08-08T16:25:53.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 16,
                            "state": "like",
                            "createdAt": "2023-08-08T16:25:54.000Z",
                            "updatedAt": "2023-08-08T16:25:54.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 17,
                            "state": "like",
                            "createdAt": "2023-08-08T16:25:56.000Z",
                            "updatedAt": "2023-08-08T16:25:56.000Z",
                            "userId": 2,
                            "postId": 5,
                            "User": {
                                "id": 2,
                                "username": "potatUser",
                                "picturePath": "image-1691430498994.png"
                            }
                        },
                        {
                            "id": 18,
                            "state": "dislike",
                            "createdAt": "2023-08-08T16:26:01.000Z",
                            "updatedAt": "2023-08-08T16:26:01.000Z",
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

const groupReaction = {
    createReaction,
    getReaction,
    deleteReaction,
    editReaction,
    allReactionsOnPost
}


module.exports = groupReaction;