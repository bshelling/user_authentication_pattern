const mg = require('mongoose')
const { Schema } = mg


const UserSchema = new Schema({
    username: String,
    password: String
})

module.exports.User = mg.model('User',UserSchema)