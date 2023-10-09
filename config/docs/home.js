const search={
    tags:["Home Page"],
    description:`search for (users,posts,groups) by string passed in query</br >
    you must be authorized </br>
    <h3> Note 1: send token in bearer </h3>`,
    security: [{
        bearerAuth: []
    }],
    parameters:[
        {
            in: 'query',
            name: 'text',
            type: 'application/json',
            description: 'Key-value pairs for filtering users,posts,groups',
            schema:{
                type:"Object",
                example:{
                    "text":"u"     
                }
            }            
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
                            "msg": "4 Search Results Found !!",
                            "users": [
                              {
                                "id": 2,
                                "username": "updatedUsername",
                                "picturePath": "image-1690691170494.PNG",
                              },
                              {
                                "id": 5,
                                "username": "User3",
                                "picturePath": null,
                              }
                            ],
                            "groups": [
                              {
                                "id": 1,
                                "groupName": "potatoGroup",
                                "groupDescription": "potatoDescription",
                                "groupPicture": null,
                                "createdAt": "2023-08-02T10:42:26.000Z",
                                "updatedAt": "2023-08-02T10:42:26.000Z"
                              }
                            ],
                            "posts": [
                              {
                                "id": 4,
                                "text": "updated text for post",
                                "picture": "image-1690973695852.PNG",
                                "createdAt": "2023-08-01T18:03:25.000Z",
                                "state": "public",
                                "updatedAt": "2023-08-02T10:54:55.000Z",
                                "userId": 5,
                                "commentsCount": 1,
                                "likesCount": 1,
                                "dislikesCount": 0,
                                "User": {
                                  "id": 5,
                                  "username": "User3",
                                  "picturePath": null
                                },
                                "Comments": [
                                  {
                                    "id": 7,
                                    "text": "comment text",
                                    "createdAt": "2023-08-01T18:08:31.000Z",
                                    "updatedAt": "2023-08-01T18:08:31.000Z",
                                    "userId": 5,
                                    "postId": 4,
                                    "User": {
                                      "id": 5,
                                      "username": "User3",
                                      "picturePath": null
                                    }
                                  }
                                ],
                                "Reactions": [
                                  {
                                    "id": 3,
                                    "state": "like",
                                    "createdAt": "2023-08-01T18:08:26.000Z",
                                    "updatedAt": "2023-08-01T18:08:26.000Z",
                                    "userId": 5,
                                    "postId": 4,
                                    "User": {
                                      "id": 5,
                                      "username": "User3",
                                      "picturePath": null
                                    }
                                  }
                                ]
                              }
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
    }
}


const news={
  tags:["Home Page"],
  description:`get your posts and your friends posts sorted by update time</br >
  you must be authorized </br>
  <h3> Note 1: send token in bearer </h3>`,
  security: [{
      bearerAuth: []
  }],
  responses:{
      200:{
          description:"OK",
          content:{
              "application/json":{
                  schema:{
                      type:"Object",
                      example:{
                        "posts": [
                          {
                            "id": 4,
                            "text": "updated text for post",
                            "picture": "image-1690973695852.PNG",
                            "createdAt": "2023-08-01T18:03:25.000Z",
                            "state": "public",
                            "updatedAt": "2023-08-02T10:54:55.000Z",
                            "userId": 5,
                            "commentsCount": 1,
                            "likesCount": 1,
                            "dislikesCount": 0,
                            "User": {
                              "id": 5,
                              "username": "User3",
                              "picturePath": null
                            },
                            "Comments": [
                              {
                                "id": 7,
                                "text": "comment text",
                                "createdAt": "2023-08-01T18:08:31.000Z",
                                "updatedAt": "2023-08-01T18:08:31.000Z",
                                "userId": 5,
                                "postId": 4,
                                "User": {
                                  "id": 5,
                                  "username": "User3",
                                  "picturePath": null
                                }
                              }
                            ],
                            "Reactions": [
                              {
                                "id": 3,
                                "state": "like",
                                "createdAt": "2023-08-01T18:08:26.000Z",
                                "updatedAt": "2023-08-01T18:08:26.000Z",
                                "userId": 5,
                                "postId": 4,
                                "User": {
                                  "id": 5,
                                  "username": "User3",
                                  "picturePath": null
                                }
                              }
                            ]
                          },
                          {
                            "id": 6,
                            "text": "text for post",
                            "picture": "image-1690913824592.PNG",
                            "createdAt": "2023-08-01T18:17:04.000Z",
                            "state": "public",
                            "updatedAt": "2023-08-01T18:17:04.000Z",
                            "userId": 2,
                            "commentsCount": 0,
                            "likesCount": 0,
                            "dislikesCount": 0,
                            "User": {
                              "id": 2,
                              "username": "updatedUsername",
                              "picturePath": "image-1690691170494.PNG"
                            },
                            "Comments": [],
                            "Reactions": []
                          },
                          {
                            "id": 5,
                            "text": "text for post",
                            "picture": "image-1690913287266.PNG",
                            "createdAt": "2023-08-01T18:08:07.000Z",
                            "state": "public",
                            "updatedAt": "2023-08-01T18:08:07.000Z",
                            "userId": 2,
                            "commentsCount": 0,
                            "likesCount": 0,
                            "dislikesCount": 0,
                            "User": {
                              "id": 2,
                              "username": "updatedUsername",
                              "picturePath": "image-1690691170494.PNG"
                            },
                            "Comments": [],
                            "Reactions": []
                          }
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
  }
}


const home={
    search,
    news
}

module.exports=home;