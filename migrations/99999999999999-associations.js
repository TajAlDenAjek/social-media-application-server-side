 'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    //posts
    queryInterface.addConstraint('posts',{
      fields:['userId'],
      type:'foreign key',
      name:'post_user_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    // comments
    queryInterface.addConstraint('Comments',{
      fields:['userId'],
      type:'foreign key',
      name:'comment_user_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('Comments',{
      fields:['postId'],
      type:'foreign key',
      name:'comment_post_association',
      references:{
        table:'posts',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    // reactions
    queryInterface.addConstraint('Reactions',{
      fields:['userId'],
      type:'foreign key',
      name:'reaction_user_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('Reactions',{
      fields:['postId'],
      type:'foreign key',
      name:'reaction_post_association',
      references:{
        table:'posts',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    //releationships
    queryInterface.addConstraint('relationships',{
      fields:['firstUserId'],
      type:'foreign key',
      name:'relationships_firstUser_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('relationships',{
      fields:['secondUserId'],
      type:'foreign key',
      name:'relationships_secondUser_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    //chats
    queryInterface.addConstraint('chats',{
      fields:['senderUserId'],
      type:'foreign key',
      name:'chats_senderUserId_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('chats',{
      fields:['reciverUserId'],
      type:'foreign key',
      name:'chats_reciverUserId_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    //groupusers
    queryInterface.addConstraint('groupusers',{
      fields:['userId'],
      type:'foreign key',
      name:'groupusers_user_association',
      references:{
        table:'users',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('groupusers',{
      fields:['groupId'],
      type:'foreign key',
      name:'groupusers_group_association',
      references:{
        table:'groups',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    //groupposts
    queryInterface.addConstraint('groupposts',{
      fields:['groupUserId'],
      type:'foreign key',
      name:'groupposts_groupUser_association',
      references:{
        table:'GroupUsers',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('groupposts',{
      fields:['groupId'],
      type:'foreign key',
      name:'groupposts_group_association',
      references:{
        table:'groups',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    queryInterface.addConstraint('groupposts',{
      fields:['postId'],
      type:'foreign key',
      name:'groupposts_post_association',
      references:{
        table:'posts',
        field:'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE'
    });
    // queryInterface.addConstraint('groupposts',{
    //   fields:['userId'],
    //   type:'foreign key',
    //   name:'groupposts_user_association',
    //   references:{
    //     table:'Posts',
    //     field:'id'
    //   },
    //   onUpdate: 'CASCADE',
    //   onDelete: 'CASCADE'
    // });
  },

  async down (queryInterface, Sequelize) {
    //posts
    await queryInterface.removeConstraint('posts', 'post_user_association');
    //comments
    await queryInterface.removeConstraint('comments', 'comment_user_association');
    await queryInterface.removeConstraint('comments', 'comment_post_association');
    //reactions
    await queryInterface.removeConstraint('Reactions', 'reaction_user_association');
    await queryInterface.removeConstraint('Reactions', 'reaction_post_association');
    //relationships
    await queryInterface.removeConstraint('relationships', 'relationships_firstUser_association');
    await queryInterface.removeConstraint('relationships', 'relationships_secondUser_association');
    //chats
    await queryInterface.removeConstraint('chats', 'chats_senderUserId_association');
    await queryInterface.removeConstraint('chats', 'chats_reciverUserId_association');
    //groupusers
    await queryInterface.removeConstraint('groupusers', 'groupusers_user_association');
    await queryInterface.removeConstraint('groupusers', 'groupusers_group_association');
    //groupposts
    await queryInterface.removeConstraint('groupposts', 'groupposts_groupUser_association');
    await queryInterface.removeConstraint('groupposts', 'groupposts_group_association');
    await queryInterface.removeConstraint('groupposts', 'groupposts_post_association');
    // await queryInterface.removeConstraint('groupposts', 'groupposts_user_association');
  }
};
