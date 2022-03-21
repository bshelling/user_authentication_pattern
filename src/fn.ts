
import * as ag from 'argon2'
import * as jwt from 'jsonwebtoken'
import * as msg from './msg'
import * as dotenv from 'dotenv'
import * as express from 'express'
import * as crypto from 'crypto'

dotenv.config()

export const verify = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
 
    try {
        if (!await jwt.verify(req.cookies.accessToken, "process.env.jwtSecret")) res.redirect("403")
            next()
    }
    catch (err) {
        res.redirect(403, '/login')
    }
}

export const sign = async () => {
    const signed = await jwt.sign({
        type: 'appUser',
        role: 'appPaid'
    }, "process.env.jwtSecret",{
        expiresIn: '30s'
    })
    return signed
}

export const resetpass = async () => {
    const signed = await jwt.sign({
        type: 'appUser',
        action: 'reset'
    }, "process.env.jwtSecret",{
        expiresIn: '5m'
    })
    return signed
}

export const hashPw = async (pw: string) => {

    try {
        const hash = await ag.hash(pw)
        return hash
    }
    catch (err) {
        return err
    }

}

export const genHash = (bytes: number) => {
    return crypto.randomBytes(bytes).toString('hex')
}

export const comparePw = async (hash: any, pw: string) => {
  
    if (await ag.verify(hash, pw)) {
        return true
    }
    else {
        return false
    }
}

