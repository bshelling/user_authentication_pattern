

const Express = require('express')
const app = Express()
const mg = require('mongoose')

const bp = require('body-parser')
const cors = require('cors')
const fn = require('./fn')
const msg = require('./msg')
const dotenv = require('dotenv')

dotenv.config()

/**
 * Models
 */
const user = require('./models/User')
const { redirect } = require('express/lib/response')

const PORT = 3000
const HOST = '0.0.0.0'

app.use(bp.json())
app.use(bp.urlencoded({extended:true}))
app.use(cors())

const dbUser = 'admin'
const dbPw = 'adminpwd'
const dbHost = 'localhost'
const dbPort = '27018'
const dbName = 'authDb'

const connect = async () => {
    await mg.connect(`mongodb://${dbUser}:${dbPw}@${dbHost}:${dbPort}/${dbName}?authSource=admin`)
  
}
connect().catch(error => console.log("Connection Error: "+ error))


/**
 * path: /
 */
app.get('/',(req,res) => {
    
    return res.json({
        "title":"Jwt Authentication Service",
        "author":"bshelling@gmail.com",
        "version":"1.0"
    })

}) 

/**
 * path: /paywall
 */
app.get('/paywall',fn.verify,(req,res) => {

    return res.json({
        page: 'user-dashboard'
    })
     
})


/**
 * path: /authenticate
 */
app.post('/authenticate',async (req,res)=>{

    try {
    
        const usr = await user.User.findOne({username:req.body.username}).exec()
        if(!await fn.comparePw(usr.password,req.body.password)) return redirect(403,'/')
        await fn.sign()
        return res.json({
            msg: await fn.comparePw(usr.password,req.body.password),
            accessToken: await fn.sign()
        })


    }
    catch(err){
        
        res.redirect(403,'/authenticate')
    }

})




/**
 * path: /register
 */
app.post('/register',async (req,res) =>{

    try{
        if(await user.User.exists({username : req.body.username})) return res.json({msg:msg.userExists});
        const usr = new user.User({
            username: req.body.username,
            password: await fn.hashPw(req.body.password)
        })
        await usr.save()
        return res.json({
            message: `${req.body.username} account has been created`
        })
    }
    catch(error){
        return res.json({
            error: error
        })
    }

})

/**
 * path: /reset-password
 */
app.post('/reset-password',(req,res) =>{


    return res.json({
        username: req.body.username,
        password: req.body.password
    })


})

app.listen(PORT,HOST,(err) => {
    console.log(`http://localhost:${PORT}`)
})