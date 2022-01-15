const argon2 = require('argon2')
const jwt = require('jsonwebtoken')
const msg = require('./msg')
const dotenv = require('dotenv')
dotenv.config()


module.exports.verify = async (req, res, next) => {
 
    try {
        if (!await jwt.verify(req.cookies.accessToken, process.env.jwtSecret)) res.redirect(403)
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

