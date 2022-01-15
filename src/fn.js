const argon2 = require('argon2')
const jwt = require('jsonwebtoken')
const msg = require('./msg')
const dotenv = require('dotenv')
dotenv.config()


module.exports.verify = async (req, res, next) => {
    try {
        if (!await jwt.verify('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYXBwVXNlciIsImlhdCI6MTY0MjIwNjU4Mn0.9tSUiMUc05_Q3EnLGu4TA172xwSmDB6OWwiuox5Mi2k', process.env.jwtSecret)) res.redirect(403)
            next()
    }
    catch (err) {
        res.redirect(403, '/login')
    }
}

module.exports.sign = async () => {
    const signed = await jwt.sign({
        type: 'appUser'
    }, process.env.jwtSecret)
    return signed
}

module.exports.hashPw = async (pw) => {

    try {
        const hash = await argon2.hash(pw)
        return hash
    }
    catch (err) {
        return err
    }

}

module.exports.comparePw = async (hash, pw) => {
  
    if (await argon2.verify(hash, pw)) {
        return true
    }
    else {
        return false
    }
}

