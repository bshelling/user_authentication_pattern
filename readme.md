


## SQLite3 used for development with Prisma ORM

#### Schema
```
/schema.prisma

datasource db {
    url = "file:./app.db"
    provider = "sqlite"
}

generator client {
    provider = "prisma-client-js"
}


model User {
  id        Int      @id @default(autoincrement())
  createdAt DateTime @default(now())
  email     String   @unique
  username String @unique
  name      String?
  password  String   @unique
  resetPass String?  @unique
  resetExp  Int? 
}
```
#### Run migration
```
npm run migrate:dev
```
---
## Endpoints
### User dashboard with valid webtoken
```
app.get('/dashboard', verify, (req: express.Request, res: express.Response) => {

    return res.json({
        title: 'Dashboard',
        page: 'user-dashboard'
    })

})
```

### User login
```app.post('/login', async (req: express.Request, res: express.Response) => {

    try {
        const user = await prisma.user.findUnique({
            where: { username: req.body.username },
            select: {
                password: true,
                retry: true,
                retryExp: true
            }
        })
        const pass = await comparePw(user?.password, req.body.password)


        if (pass && Number(user?.retry) <= 3) {
            const signedToken = await sign()

            await prisma.user.update({
                where: {
                    email: req.body.email
                },
                data: {
                    retry: 0,
                    retryExp: 0
                }
            })


            await res.cookie('accessToken', signedToken, { httpOnly: true, expires: new Date(Date.now() + 8 * 3600000), path: '/dashboard' })
            return res.json({
                msg: pass
            })
        }
        else {
            if (user) {


                switch (user.retry) {

                    case 3:
                        if(Number(user.retryExp) > new Date(Date.now()).valueOf()){

                            res.json({
                                message: "Your account is still locked. Please contact support to unlock your account",
                                now: new Date(Date.now()).valueOf(),
                                exp: Number(user.retryExp)
                            })

                        }
                        else{

                            await prisma.user.update({
                                where: {
                                    email: req.body.email
                                },
                                data: {
                                    retry: 1,
                                }
                            })
                            res.json({
                                message: "Your account is unlocked",
                                now: new Date(Date.now()).valueOf(),
                                exp: Number(user.retryExp)
                            })

                        }
                        break;
                    case 2:
                        await prisma.user.update({
                            where: {
                                email: req.body.email
                            },
                            data: {
                                retry:{
                                    increment: 1
                                },
                                retryExp: new Date(Date.now() + RETRY_TIMER * 60000).valueOf()
                            }
                        })
                        res.json({
                            message: `Your account has been locked for ${RETRY_TIMER} minute(s). Please try again later`
                        })
                        break;

                    default:
                        await prisma.user.update({
                            where: {
                                email: req.body.email
                            },
                            data: {
                                retry: {
                                    increment: 1
                                }
                            }
                        })
                        res.json({
                            message: "Something went wrong, please try again. "
                        })


                }




            }
            else {

                res.redirect(302, '/login')
            }

        }
    }
    catch (err) {
        console.log(err)
        res.status(500).json({
            message: "Something has gone wrong please try again"
        })
    }

})``

```


### User registration 
```
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
```

### User forgot password
```
app.post('/forgot-password', async (req: express.Request, res: express.Response) => {
    try {
        const getUser = await prisma.user.findUnique({
            where: {
                email: req.body.email
            }
        })

        if (getUser != null) {
            const token = await genHash(RESET_BYTES)
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
                resetPasswordExpiration: new Date(Date.now() + MINUTES * 60000).valueOf(),
                tokenExpiresIn: `${MINUTES} minutes`,
                urlSentToEmail: `${SITE}/reset-password/${token.toString()}`
            })
        }
        else {
            return res.status(400).json({
                message: "Email doesn't exist"
            })
        }


    }
    catch (e) {
        return res.status(500).json({
            msg: e
        })
    }



})
```

### User resets password with valid token
```
app.post('/reset-password/:token', async (req: express.Request, res: express.Response) => {

    try {

        const user = await prisma.user.findUnique({
            where: {
                resetPass: req.params.token
            }
        })
        const now = new Date(Date.now()).valueOf()

        if (user?.resetExp) {
            if (user.resetExp > now) {
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
                    expiredToken: user.resetExp > now ? true : false,
                    message: `${user.username} account password has been reset`

                })
            }
            else {

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
                    expiredToken: user.resetExp > now ? true : false,
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
    catch (e) {
        return res.status(500).json({
            message: "Something went wrong please try again"
        })
    }


})

```

### User resets password with valid token
```
app.get('/forbidden', (req: express.Request, res: express.Response) => {

    return res.json({
        msg: "Please try again"
    })
})
```
---
## Middleware and methods

### Verify if token is valid
```
export const verify = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
 
    try {
        if (!await jwt.verify(req.cookies.accessToken, "process.env.jwtSecret")) res.redirect("403")
            next()
    }
    catch (err) {
        res.redirect(403, '/login')
    }
}
```

### Sign Token
```
export const sign = async () => {
    const signed = await jwt.sign({
        type: 'appUser',
        role: 'appPaid'
    }, "process.env.jwtSecret",{
        expiresIn: '30s'
    })
    return signed
}
```


### Hash password

```
export const hashPw = async (pw: string) => {

    try {
        const hash = await ag.hash(pw)
        return hash
    }
    catch (err) {
        return err
    }
}

```

### Basic hash generator

```
export const genHash = (bytes: number) => {
    return crypto.randomBytes(bytes).toString('hex')
}
```

### Verify password
```
export const comparePw = async (hash: any, pw: string) => {
  
    if (await ag.verify(hash, pw)) {
        return true
    }
    else {
        return false
    }
}

```