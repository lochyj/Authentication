import DatabaseHandler from './databaseHandler.mjs';

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
var cookieParser = require('cookie-parser');

export default class Authentication {
    constructor (options) {
        this.options = options;

        // Defaults:
        this.options.loginUrl = this.options.loginUrl || "/login";
        this.options.registerUrl = this.options.registerUrl || "/register";
        this.options.DBName = this.options.DBName || "auth";
        this.options.mongoUrl = this.options.mongoUrl || "mongodb://127.0.0.1:27017/" /* 127.0.0.1 is used in place of localhost due to a bug i can't fix \('_')/ */
        this.options.port = this.options.port || "5500";

        this.options.min_usr_characters = this.options.min_usr_characters || 4;

        // Responses:
        this.options.errors = {
            null_username_password: "Username and password is a null value",
            short_username: `Username is too short; it must be at least ${this.options.min_usr_characters} characters long`,
        };
    }

    authenticate_request (request, response, next) {

    }

    async start_server() {
        app.use(express.json());
        app.use(cookieParser());

        this.DB = new DatabaseHandler({
            mongoUrl: this.options.mongoUrl,
            DBName: this.options.DBName
        });


        app.post('/auth/register', async(req, res) => {
            //TODO: Update to be better I guess lol
            if (!req.body.username || !req.body.password) {
                res.status(400).json({
                    message: 'Please provide a username and password'
                })
                return
            }
            const { username, password } = req.body
            const user = users.find(user => user.username === username)
            if (user) {
                res.status(400).json({ error: 'Username already exists' })
            } else {
                const hash = await bcrypt.hash(password, 10)
                store(username, hash)
                updateUsers()
                res.status(200).json({ message: 'User created' })
            }
        })

    }

    create_user(username, password) {
        if (username == null || password == null) return this.options.errors.null_username_password;
        if (username.length < this.options.min_usr_characters) return this.options.errors.short_username;
        this.encrypt_password(password).then((hash) => {
            this.DB.add_user_to_db(username, hash);
        }, (err) => {
            handle_error(err, "Failed to encrypt password");
        });
    }

    generate_access_token (user) {
        const token = req.cookies.accessToken;

        // If there is no token in the request return an error and redirect to login
        if (token == null) return res.sendStatus(401).redirect(this.options.loginUrl);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        })
    }

    handle_error(error, message) {
        console.log(`
        | ${error} | 
        | ${message} |
        `);
    }
}