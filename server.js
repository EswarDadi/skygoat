const express=require("express");
const {open}=require("sqlite");
const sqlite3=require("sqlite3").verbose();
const path=require("path")
const databasePath=path.join(__dirname,"users.db");
const app=express();
app.use(express.json());
const bcrypt = require("bcryptjs"); 
const jwt = require("jsonwebtoken");

let database=null
const startServer=async()=>{
    try {
        database = await open({
          filename: databasePath,
          driver: sqlite3.Database,
        });
    await database.run(`
        CREATE TABLE IF NOT EXISTS user(
            ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    
    `);
    app.listen(5005, () =>
        console.log("Server Running at http://localhost:5005/")
      );
} catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
}

app.post("/signup/", async (request, response) => {
    const { username, password } = request.body;
    const hashPassword = await bcrypt.hash(password, 10);
    
    try {
        const userQuery = `SELECT * FROM user WHERE username=?`;
        const dbUser = await database.get(userQuery, [username]);
        
        console.log("Existing user:", dbUser);
        
        if (dbUser) {
            response.status(400).send("User already exists");
        } else {
            const createUser = `
                INSERT INTO user(username, password)
                VALUES(?, ?)
            `;
            const { lastID } = await database.run(createUser, [username, hashPassword]);
            
            response.send(`Created user with ID ${lastID}`);
        }
    } catch (error) {
        console.log("Signup Error:", error);
        response.status(500).send("Internal Server Error");
    }
});


//login api

app.post("/login/",async(request,response)=>{
    const {username,password}=request.body
    const selectUserQuery=`SELECT*FROM user where username='${username}'`
    const dbUser=await database.run(selectUserQuery)
    if(dbUser===undefined){
        response.status(400);
        response.send("Not a valid user");
    }else{
        const checkPassword = await bcrypt.compare(password, dbUser.password);
        if(checkPassword===true){
            response.send("user logged in!");
        }
        else{
            response.status(400);
            response.send("Invalid password")
        }
    }
})

// middlware to authenticate
const authenticateToken = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers["authorization"];
    if (authHeader !== undefined) {
      jwtToken = authHeader.split(" ")[1];
    }
    if (jwtToken === undefined) {
      response.status(401);
      response.send("Invalid JWT Token");
    } else {
      jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
        if (error) {
          
          response.status(401);
          response.send("Invalid JWT Token");
        } else {
            request.username = payload.username;
          next();
        }
      });
    }
  };
  app.get("/user/", authenticateToken, async (request, response) => {
    let { username } = request;
    const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
    const userDetails = await db.get(selectUserQuery,[username]);
    response.send(userDetails);
  });
startServer()
module.exports=database