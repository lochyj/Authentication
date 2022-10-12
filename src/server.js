const Authentication = require("./authentication.js");

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mongo = require('mongodb').MongoClient
const bcrypt = require('bcrypt')
var cookieParser = require('cookie-parser')

app.use(express.json())
app.use(cookieParser())

var Auth = new Authentication({
    port: "80"
});

Auth.start_server();
