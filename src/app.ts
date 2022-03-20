import express from 'express'
import * as bp from 'body-parser'
import * as cors from 'cors'
import * as cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv'
import { verify, comparePw, hashPw, sign, resetpass, genHash } from './fn'
import * as msg from './msg'
import { PrismaClient } from '@prisma/client'

dotenv.config()

const PORT = 3000
const HOST = '0.0.0.0'

const app = express()
app.use(bp.json())
app.use(bp.urlencoded({ extended: true }))
app.use(cookieParser.default())
app.use(cors.default())



const prisma = new PrismaClient()

const TESTPW = ""
const MINUTES = 3
const SITE = 'http://localhost:300'

// /**
//  * path: /
//  */
app.get('/',(req: express.Request,res: express.Response) => {

    return res.json([{
        "title":"Jwt Authentication Service",
        "author":"bshelling@gmail.com",
        "version":"1.0"
    }])

}) 

// /**
//  * path: /Dashboard
//  */
app.get('/dashboard',verify,(req:express.Request,res: express.Response) => {

    return res.json({
        title: 'Dashboard',
        page: 'user-dashboard'
    })

})

// /**
//  * path: /login
//  */
app.post('/login', async (req: express.Request, res: express.Response) => {

    try {
        const user = await prisma.user.findUnique({where:{username: req.body.username},
            select: {
                password: true
            }
        })
        const pass = await comparePw(user?.password, req.body.password)
        if (pass) {
             const signedToken = await sign()
             await res.cookie('accessToken',signedToken, {httpOnly: true,expires: new Date(Date.now() + 8 * 3600000), path: '/dashboard'} )
            return res.json({
                msg: pass
            })
        }
        else {
            res.redirect(302,'/login')
        }
    }
    catch (err) {
        console.log(err)
        res.status(500).json({
            message: "Something has gone wrong please try again"
        })
    }

})

/**
 * path: /register
 */
app.post('/register', async (req: express.Request, res: express.Response) => {

    try {
        const hashed: any = await hashPw(req.body.password)
        const newUser = await prisma.user.create({
            data: {
                name: req.body.name,
                username: req.body.username,
                email: req.body.email,
                password: hashed
            },
        })
        return res.json({
            message: `${req.body.username} account has been created`
        })
    }
    catch (error) {
        return res.json({
            error: error
        })
    }

})

app.post('/forgot-password', async (req: express.Request,res: express.Response) =>{
    try{
        const getUser = await prisma.user.findUnique({
            where:{
                email: req.body.email
            }
        })

        if(getUser != null){
            const token = await genHash()
            const addResetToken = await prisma.user.update({
                where: {
                    email: req.body.email
                },
                data: {
                    resetPass: token,
                    resetExp: new Date(Date.now() + MINUTES * 60000).valueOf()
                }
            })
            return res.json({
                resetPasswordToken: token,
                resetPasswordExpiration: new Date(Date.now() + MINUTES* 60000).valueOf(),
                tokenExpiresIn: `${MINUTES} minutes`,
                urlSentToEmail: `${SITE}/reset-password/${token.toString()}`
            })
        }
        else{
            return res.status(400).json({
                message: "Email doesn't exist"
            })
        }

    
    }
    catch(e){
        return res.status(500).json({
            msg: e
        })
    }



})


// /**
//  * path: /reset-password
//  */
app.post('/reset-password/:token',async (req: express.Request,res: express.Response) =>{

    try {

        const user = await prisma.user.findUnique({
            where:{
                resetPass: req.params.token
            }
        })
        const now = new Date(Date.now()).valueOf()

        if(user?.resetExp){
            if(user.resetExp > now){
                const hashed: any = await hashPw(req.body.password)
                const addResetToken = await prisma.user.update({
                    where: {
                        email: user.email
                    },
                    data: {
                        password: hashed,
                        resetExp: 0,
                        resetPass: ""
                    }
                })

                return res.json({
                    expiration: user.resetExp,
                    now: now,
                    expiredToken: user.resetExp > now? true: false,
                    message: `${user.username} account password has been reset`

                })
            }
                else{

                const addResetToken = await prisma.user.update({
                    where: {
                        email: user.email
                    },
                    data: {
                        resetExp: 0,
                        resetPass: ""
                    }
                })

                return res.json({
                    message: "Reset password has expired. Please try again if needed.",
                    expiredToken: user.resetExp > now? true: false,
                    expiration: user.resetExp,
                    now: now
                })
            }

        }
         else {
             return res.json({
                    message: `Are you trying to reset your password? Visit ${SITE}/forgot-password to reset your password`,
            })
        }


    }
    catch(e){
        return res.status(500).json({
            message: "Something went wrong please try again"
        })
    }


})

// /**
//  * path: /forbidden
//  */
app.get('/forbidden',(req: express.Request,res: express.Response)=>{

    return res.json({
        msg: "Please try again"
    })
})

app.listen(PORT, HOST, () => {
    console.log(`http://localhost:${PORT}`)
})