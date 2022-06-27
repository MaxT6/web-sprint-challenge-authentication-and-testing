const router = require('express').Router();
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../users/users-model')
// const {validateCredentials} = require('../middleware/restricted')


router.
post('/register', async (req, res, next) => {
  try{
      const {username, password } = req.body;
      if (!username || !password) {
        res.status(404).json({message: "username and password required"})
      } else if(username) {
        const takenUser = await User.findBy({ username }).first();
        if (takenUser) {
          next({status: 400, message: "username taken"})
        } else {
          const hash = bcrypt.hashSync(password, 8);
        const newUser = await User.add({ username, password: hash})
        res.status(201).json(newUser)
        }
      } 
  } catch(err) {
    next(err)
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const {username, password} = req.body
    const authUser = await User.findBy({username}).first();
      if (authUser.username && bcrypt.compareSync(password, authUser.password)) {
        const token = generateToken(authUser);
        res.status(200).json({message: `welcome, ${authUser.username}`, token})
      } else if(!username || !password) {
        res.status(400).json({message: "username and password required"})
      } else {
        next({ status: 401, message: 'invalid credentials'})
      }
  } catch(err) {
    next(err)
  }
  
});

function generateToken(user) {
  const payload = {
    subect: user.id,
    username: user.username,
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;


/* completed task

  1- In order to register a new account the client must provide `username` and `password`:
      {
        "username": "Captain Marvel", // must not exist already in the `users` table
        "password": "foobar"          // needs to be hashed before it's saved
      }

    2- On SUCCESSFUL registration,
      the response body should have `id`, `username` and `password`:
      {
        "id": 1,
        "username": "Captain Marvel",
        "password": "2a$08$jG.wIGR2S4hxuyWNcBf9MuoC4y0dNy7qC/LbmtuFBSdIhWks2LhpG"

           You are welcome to build additional middlewares to help with the endpoint's functionality.
    DO NOT EXCEED 2^8 ROUNDS OF HASHING!

  
    3- On FAILED registration due to `username` or `password` missing from the request body,
      the response body should include a string exactly as follows: "username and password required".

    4- On FAILED registration due to the `username` being taken,
      the response body should include a string exactly as follows: "username taken".
      }

*/


/*
    IMPLEMENT
    You are welcome to build additional middlewares to help with the endpoint's functionality.

    1- In order to log into an existing account the client must provide `username` and `password`:
      {
        "username": "Captain Marvel",
        "password": "foobar"
      }

    2- On SUCCESSFUL login,
      the response body should have `message` and `token`:
      {
        "message": "welcome, Captain Marvel",
        "token": "eyJhbGciOiJIUzI ... ETC ... vUPjZYDSa46Nwz8"
      }

    3- On FAILED login due to `username` or `password` missing from the request body,
      the response body should include a string exactly as follows: "username and password required".

    4- On FAILED login due to `username` not existing in the db, or `password` being incorrect,
      the response body should include a string exactly as follows: "invalid credentials".
  */