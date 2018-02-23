'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        return queryInterface.createTable('user_registration_profile',
            {
               id: {
                    type: Sequelize.UUID,
                    primaryKey: true,
                    defaultValue: Sequelize.UUIDV4
                }, activation_key: {
                    type: Sequelize.STRING
                }, activation_expires: {
                    type: Sequelize.DATE
                }, reset_key : {
                    type: Sequelize.STRING,
                    defaultValue: undefined
                }, reset_expires : {
                    type: Sequelize.DATE,
                    defaultValue: undefined
                }, verification_key : {
                    type: Sequelize.STRING,
                    defaultValue: undefined
                }, verification_expires : {
                    type: Sequelize.DATE,
                    defaultValue: undefined
                },
                user_email: {
                    type: Sequelize.STRING,
                    references: {
                        model: 'user',
                        key: 'email'
                    }
                }
            },
            {
                sync: {force: true}
            }
        );
    },

    down: function (queryInterface, Sequelize) {
        return queryInterface.dropTable('user_registration_profile');
    }
};