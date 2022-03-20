import express from 'express'
import * as bp from 'body-parser'
import * as cors from 'cors'
import * as cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv'
import { verify, comparePw, hashPw, sign } from './fn'
import * as msg from './msg'

dotenv.config()

const PORT = 3000
const HOST = '0.0.0.0'

const app = express()
app.use(bp.json())
app.use(bp.urlencoded({ extended: true }))
app.use(cookieParser.default())
app.use(cors.default())

const TESTPW = ""

// /**
//  * path: /
//  */
// app.get('/',(req: express.Request,res: express.Response) => {

//     return res.json([{
//         "title":"Jwt Authentication Service",
//         "author":"bshelling@gmail.com",
//         "version":"1.0"
//     }])

// }) 


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

        const signedToken = await sign()
        await res.cookie('accessToken',signedToken, {httpOnly: true,expires: new Date(Date.now() + 8 * 3600000), path: '/dashboard'} )
        const pass = await comparePw(TESTPW, req.body.password)

        if (pass) {
            return res.json({
                msg: pass
            })
        }
        else {

            res.redirect(302,'/login')
        }
    }
    catch (err) {

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
        const hashed = await hashPw(req.body.password)
        return res.json({
            message: `${req.body.username} account has been created`,
            password: hashed
        })
    }
    catch (error) {
        return res.json({
            error: error
        })
    }

})

// /**
//  * path: /reset-password
//  */
// app.post('/reset-password',(req: express.Request,res: express.Response) =>{


//     return res.json({
//         username: req.body.username,
//         password: req.body.password
//     })


// })

app.get('/forbidden',(req: express.Request,res: express.Response)=>{

    return res.json({
        msg: "Please try again"
    })
})

app.listen(PORT, HOST, () => {
    console.log(`http://localhost:${PORT}`)
})