const createGroup = {
    tags: ["group"],
    "summary": "Create Group",
    "operationId": "CreateGroup",
    "parameters": [],
    "requestBody": {
        "description": "",
        "content": {
            "application/json": {
                "schema": {
                    "example": {
                        "groupName": "name",
                        "groupDescription": "des..."
                    }
                },
                "example": {
                    "groupName": "name",
                    "groupDescription": "des..."
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
                        "example": {
                            "msg": "Group created successfully",
                            "group": {
                                "createdAt": "2023-08-08T13:03:58.695Z",
                                "updatedAt": "2023-08-08T13:03:58.696Z",
                                "id": 2,
                                "groupName": "name",
                                "groupDescription": "des..."
                            }
                        }
                    },
                    "example": {
                        "msg": "Group created successfully",
                        "group": {
                            "createdAt": "2023-08-08T13:03:58.695Z",
                            "updatedAt": "2023-08-08T13:03:58.696Z",
                            "id": 2,
                            "groupName": "name",
                            "groupDescription": "des..."
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
                        "example": {
                            "msg": "failed",
                            "errors": {
                                "groupName": [
                                    "The groupName field is required."
                                ],
                                "groupDescription": [
                                    "The groupDescription field is required."
                                ]
                            }
                        }
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "groupName": [
                                "The groupName field is required."
                            ],
                            "groupDescription": [
                                "The groupDescription field is required."
                            ]
                        }
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "example": {
                            "msg": "Authentication invalid"
                        }
                    },
                    "example": {
                        "msg": "Authentication invalid"
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

const deleteGroup = {
    "tags": [
        "group"
    ],
    "summary": "Delete Group (Admin)",
    "operationId": "DeleteGroup(Admin)",
    "parameters": [
        {
            "in": "path",
            "name": "id",
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
                                    "msg": "Group deleted successfully"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Group deleted successfully"
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

const getGroup = {
    "tags": [
        "group"
    ],
    "summary": "Get Group",
    "operationId": "GetGroup",
    "parameters": [
        {
            "in": "path",
            "name": "id",
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
                                    "msg": "success",
                                    "group": {
                                        "id": 1,
                                        "groupName": "name",
                                        "groupDescription": "des...",
                                        "groupPicture": null,
                                        "createdAt": "2023-08-01T23:10:34.000Z",
                                        "updatedAt": "2023-08-08T13:06:11.000Z"
                                    },
                                    "role": "Owner"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "success",
                        "group": {
                            "id": 1,
                            "groupName": "name",
                            "groupDescription": "des...",
                            "groupPicture": null,
                            "createdAt": "2023-08-01T23:10:34.000Z",
                            "updatedAt": "2023-08-08T13:06:11.000Z"
                        },
                        "role": "Owner"
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


const editGroup = {
    "tags": [
        "group"
    ],
    "summary": "Edit Group",
    "operationId": "EditGroup",
    "parameters": [
        {
            "in": "path",
            "name": "id",
            "schema": {
                "type": "string"
            },
            "required": true
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
                                "groupName": "name",
                                "groupDescription": "des..."
                            }
                        }
                    ]
                },
                "example": {
                    "groupName": "name",
                    "groupDescription": "des..."
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
                                    "msg": "group updated successfully",
                                    "group": [
                                        1
                                    ]
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "group updated successfully",
                        "group": [
                            1
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
                                    "msg": "failed",
                                    "errors": {
                                        "groupName": [
                                            "The groupName field is required."
                                        ],
                                        "groupDescription": [
                                            "The groupDescription field is required."
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "groupName": [
                                "The groupName field is required."
                            ],
                            "groupDescription": [
                                "The groupDescription field is required."
                            ]
                        }
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Authentication invalid"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Authentication invalid"
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
                                    "msg": "Group Not found "
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Group Not found "
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

const userGroups = {
    "tags": [
        "group"
    ],
    "summary": "My Groups",
    "operationId": "MyGroups",
    "parameters": [],
    "responses": {
        "200": {
            "description": "OK",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "groups": [
                                        {
                                            "id": 1,
                                            "groupName": "name",
                                            "groupDescription": "des...",
                                            "groupPicture": null,
                                            "createdAt": "2023-08-01T23:10:34.000Z",
                                            "updatedAt": "2023-08-08T13:06:11.000Z",
                                            "GroupUser": {
                                                "id": 1,
                                                "groupId": 1,
                                                "userId": 2,
                                                "state": "Owner",
                                                "createdAt": "2023-08-01T23:10:34.000Z",
                                                "updatedAt": "2023-08-01T23:10:34.000Z",
                                                "GroupId": 1,
                                                "UserId": 2
                                            }
                                        },
                                        {
                                            "id": 2,
                                            "groupName": "name",
                                            "groupDescription": "des...",
                                            "groupPicture": null,
                                            "createdAt": "2023-08-08T13:03:58.000Z",
                                            "updatedAt": "2023-08-08T13:03:58.000Z",
                                            "GroupUser": {
                                                "id": 2,
                                                "groupId": 2,
                                                "userId": 2,
                                                "state": "Owner",
                                                "createdAt": "2023-08-08T13:03:59.000Z",
                                                "updatedAt": "2023-08-08T13:03:59.000Z",
                                                "GroupId": 2,
                                                "UserId": 2
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "example": {
                        "groups": [
                            {
                                "id": 1,
                                "groupName": "name",
                                "groupDescription": "des...",
                                "groupPicture": null,
                                "createdAt": "2023-08-01T23:10:34.000Z",
                                "updatedAt": "2023-08-08T13:06:11.000Z",
                                "GroupUser": {
                                    "id": 1,
                                    "groupId": 1,
                                    "userId": 2,
                                    "state": "Owner",
                                    "createdAt": "2023-08-01T23:10:34.000Z",
                                    "updatedAt": "2023-08-01T23:10:34.000Z",
                                    "GroupId": 1,
                                    "UserId": 2
                                }
                            },
                            {
                                "id": 2,
                                "groupName": "name",
                                "groupDescription": "des...",
                                "groupPicture": null,
                                "createdAt": "2023-08-08T13:03:58.000Z",
                                "updatedAt": "2023-08-08T13:03:58.000Z",
                                "GroupUser": {
                                    "id": 2,
                                    "groupId": 2,
                                    "userId": 2,
                                    "state": "Owner",
                                    "createdAt": "2023-08-08T13:03:59.000Z",
                                    "updatedAt": "2023-08-08T13:03:59.000Z",
                                    "GroupId": 2,
                                    "UserId": 2
                                }
                            }
                        ]
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Authentication invalid"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Authentication invalid"
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

const createJoinRequest = {
    "tags": [
        "group"
    ],
    "summary": "Join Request",
    "operationId": "JoinRequest",
    "parameters": [
        {
            "in": "path",
            "name": "id",
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
                                    "msg": "canceled successfully"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "canceled successfully"
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized",
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "allOf": [
                            {
                                "example": {
                                    "msg": "Authentication invalid"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "Authentication invalid"
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

const getJoinRequests = {
    "tags": [
        "group"
    ],
    "summary": "get Join Requests (Admin)",
    "operationId": "getJoinRequests(Admin)",
    "parameters": [
        {
            "in": "path",
            "name": "id",
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
                                    "users": [
                                        {
                                            "userId": 2,
                                            "state": "pending",
                                            "createdAt": "2023-08-08T13:20:45.000Z",
                                            "User": {
                                                "username": "potatUser"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "example": {
                        "users": [
                            {
                                "userId": 2,
                                "state": "pending",
                                "createdAt": "2023-08-08T13:20:45.000Z",
                                "User": {
                                    "username": "potatUser"
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


const getMembers = {
    "tags": [
        "group"
    ],
    "summary": "Members",
    "operationId": "Members",
    "parameters": [
        {
            "in": "path",
            "name": "id",
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
                                    "users": [
                                        {
                                            "id": 1,
                                            "groupId": 1,
                                            "userId": 2,
                                            "state": "Owner",
                                            "createdAt": "2023-08-01T23:10:34.000Z",
                                            "updatedAt": "2023-08-01T23:10:34.000Z",
                                            "GroupId": 1,
                                            "UserId": 2
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "example": {
                        "users": [
                            {
                                "id": 1,
                                "groupId": 1,
                                "userId": 2,
                                "state": "Owner",
                                "createdAt": "2023-08-01T23:10:34.000Z",
                                "updatedAt": "2023-08-01T23:10:34.000Z",
                                "GroupId": 1,
                                "UserId": 2
                            }
                        ]
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


const modifyRole = {
    "tags": [
        "group"
    ],
    "summary": "Modify Role (Admin)",
    "operationId": "ModifyRole(Admin)",
    "parameters": [
        {
            "in": "path",
            "name": "id",
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
            "application/json": {
                "schema": {
                    "allOf": [
                        {
                            "example": {
                                "state": "kicked"
                            }
                        }
                    ]
                },
                "example": {
                    "state": "kicked"
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
                                    "msg": "updated successfully",
                                    "newRole": "normal"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "updated successfully",
                        "newRole": "normal"
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
                                        "state": [
                                            "The state field is required."
                                        ]
                                    }
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "failed",
                        "errors": {
                            "state": [
                                "The state field is required."
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
                                    "msg": "user not found"
                                }
                            }
                        ]
                    },
                    "example": {
                        "msg": "user not found"
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
    createGroup,
    deleteGroup,
    getGroup,
    editGroup,
    userGroups,
    createJoinRequest,
    getJoinRequests,
    getMembers,
    modifyRole
}


module.exports = group;