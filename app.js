require("dotenv").config()
require("./config/database").connect()
const express = require("express")
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const formidable = require('formidable')
const {v1: uuidv1} = require('uuid')
const detect = require('detect-file-type')
const app = express()

app.use(express.json())

// importing user context
const User = require(__dirname+"/model/user")

// Register
app.post("/register", async (req, res) => {
    try {
        // Get user input
        const { first_name, last_name, email, password, phone} = req.body
        const form = new formidable.IncomingForm()
        form.parse(req, async (err, fields, files) => {

          var first_name = fields.first_name
          var last_name = fields.last_name
          var phone = fields.phone
          var email = fields.email
          var password = fields.password

          if (!(email && password && first_name && last_name && phone)) {
            res.status(400).send("All input is required")
          }
          
          const oldUser = await User.findOne({ email })
          
          if (oldUser) {
            return res.status(409).send("User Already Exist. Please Login")
          }
          
          encryptedPassword = await bcrypt.hash(password, 10)

          detect.fromFile(files.image.filepath, async (err, result) => {
            // console.log(result.ext) // the extension of file
            const pictureName = uuidv1()+"."+result.ext
            const user = await User.create({
              first_name,
              last_name,
              phone,
              email: email.toLowerCase(), 
              password: encryptedPassword,
              pictureName,
            })
            
            const token = jwt.sign(
              { user_id: user._id, email },
              process.env.TOKEN_KEY,
              {
                expiresIn: "2h",
              }
              )
              user.token = token
              
            })
            //   res.status(201).json(user)
            res.send('User registered successfully')
          })
          } catch (err) {
            console.log(err)
          }
})

// Login
app.post("/login", async (req, res) => {
    try {
        // Get user input
        const { email, password } = req.body
    
        // Validate user input
        if (!(email && password)) {
          res.status(400).send("All input is required")
        }
        // Validate if user exist in our database
        const user = await User.findOne({ email })
    
        if (user && (await bcrypt.compare(password, user.password))) {
          // Create token
          const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
              expiresIn: "2h",
            }
          )
    
          // save user token
          user.token = token
    
          // user
          res.status(500).send(token)
        }
        res.status(400).send("Invalid Credentials")
      } catch (err) {
        console.log(err)
      }
})


app.get("/users", async (req, res) => {
    const users = await User.find({}, {"_id": 0, "email": 1})
    res.json(users)
})


const auth = require(__dirname+"/middleware/auth")
app.get("/profile", auth, (req, res) => {
  try {
    const { first_name, last_name, phone } = req.body
    var updatedUser = {first_name: first_name, last_name: last_name, phone: phone}
    var token = req.headers["x-access-token"]
    var decode = jwt.verify(token, process.env.TOKEN_KEY)
    var id = {email: decode.email}
    User.updateOne(id, updatedUser, (err, res) => {
      if(err){
        console.log(err)
      }
      console.log("Updated successfully")
    })
    res.send("Updated successfully")
  }
  catch(err){
    console.log(err)
  }
})


module.exports = app