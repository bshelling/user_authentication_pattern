


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