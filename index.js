const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth = require("./auth");
var cors = require("cors");

const dbConnect = require("./db/dbConnection");
const User = require("./db/userModel");
const port = 3001;
const ObjectID = require("mongodb").ObjectId;
dbConnect();

app.use(
  cors({
    origin: "*",
  })
);
// app.options("*", cors());

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
// body parser configuration
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post("/deposits", async (request, response) => {
  const token = request.headers.authorization.split(" ")[1];
  let a;
  const x = await jwt.verify(token, "RANDOM-TOKEN", function (err, decoded) {
    if (err) throw err;
    a = decoded;
  });
  if (!a) {
    response.status(500).send({
      message: "Token not valid",
    });
  } else {
    User.findOneAndUpdate(
      { _id: new ObjectID(a.userId) },
      {
        $push: {
          deposits: {
            totalAmount: request.body.totalAmount,
            currentDate: request.body.currentDate,
            goalDate: request.body.goalDate,
            monthlyPayment: request.body.monthlyPayment,
          },
        },
      },
      { new: true }
    )
      .then((res) => {
        response.status(200).send("hello");
      })
      .catch((error) => {
        response.status(500).send({
          message: "Error finding deposits",
          error,
        });
      });
  }
});

app.get("/deposits", async (request, response) => {
  const token = request.headers.authorization.split(" ")[1];
  let a;
  const x = await jwt.verify(token, "RANDOM-TOKEN", function (err, decoded) {
    if (err) throw err;
    a = decoded;
  });
  if (!a) {
    response.status(500).send({
      message: "Token not valid",
    });
  } else {
    User.find({ _id: new ObjectID(a.userId) })
      .then((res) => {
        let userDeposits = res[0].deposits;
        let depositMap = [];
        userDeposits.forEach((deposit, index) => {
          depositMap[index] = deposit;
        });
        response.status(200).send(depositMap);
      })
      .catch((error) => {
        response.status(500).send({
          message: "Error finding deposits",
          error,
        });
      });
  }
});

app.post("/register", (request, response) => {
  // hash the password
  bcrypt
    .hash(request.body.password, 10)
    .then((hashedPassword) => {
      // create a new user instance and collect the data
      const user = new User({
        email: request.body.email,
        password: hashedPassword,
      });

      // save the new user
      user
        .save()
        // return success if the new user is added to the database successfully
        .then((result) => {
          response.status(201).send({
            message: "User Created Successfully",
            result,
          });
        })
        // catch error if the new user wasn't added successfully to the database
        .catch((error) => {
          response.status(500).send({
            message: "Error creating user",
            error,
          });
        });
    })
    // catch error if the password hash isn't successful
    .catch((e) => {
      console.log(e);
      response.status(500).send({
        message: "Password was not hashed successfully",
        e,
      });
    });
});

app.post("/login", (request, response) => {
  // check if email exists
  User.findOne({ email: request.body.email })

    // if email exists
    .then((user) => {
      // compare the password entered and the hashed password found
      bcrypt
        .compare(request.body.password, user.password)

        // if the passwords match
        .then((passwordCheck) => {
          // check if password matches
          if (!passwordCheck) {
            return response.status(400).send({
              message: "Passwords does not match",
              error,
            });
          }

          // create JWT token
          const token = jwt.sign(
            {
              userId: user._id,
              userEmail: user.email,
            },
            "RANDOM-TOKEN",
            { expiresIn: "24h" }
          );

          // return success response
          response.status(200).send({
            message: "Login Successful",
            email: user.email,
            token,
          });
        })
        // catch error if password does not match
        .catch((error) => {
          response.status(400).send({
            message: "Passwords does not match",
            error,
          });
        });
    })
    // catch error if email does not exist
    .catch((e) => {
      response.status(404).send({
        message: "Email not found",
        e,
      });
    });
});

app.get("/", (request, response, next) => {
  response.json({ message: "Hey! This is your server response!" });
  next();
});

module.exports = app;
