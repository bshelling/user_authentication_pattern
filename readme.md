


## Test Server
```
docker run -e INITDB_ROOT_USERNAME=admin -e INITDB_ROOT_PASSWORD=adminpwd -p 27018:27017 --restart always -d mongo:latest
```