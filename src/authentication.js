const DatabaseHandler = require('./databaseHandler.js');
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
var cookieParser = require('cookie-parser');

module.exports = class Authentication {
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

        // Vars:
        this.errors = [];
        this.isRunning = false;

        // Init functions:
        app.use(express.json());
        app.use(cookieParser());
    }

    async start_server() {
        console.log("Starting server...");
        this.isRunning = true;

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
            //TODO: Make
            // const { username, password } = req.body
            // const user = users.find(user => user.username === username)
            // if (user) {
            //     res.status(400).json({ error: 'Username already exists' })
            // } else {
            //     const hash = await bcrypt.hash(password, 10)
            //     store(username, hash)
            //     updateUsers()
            //     res.status(200).json({ message: 'User created' })
            // }
        })

        app.post('/auth/login', async(req, res) => {
            const username = req.body.username
            const user = users.find(user => user.username === username)
            if (user) {
                const password = req.body.password
                const hash = user.password
                const isValid = await bcrypt.compare(password, hash)
                if (isValid) {
                    const accessToken = generateAccessToken({ name: user.username })
                    const refreshToken = jwt.sign({ name: user.username }, process.env.REFRESH_TOKEN_SECRET)
                    this.update_tokens_list(refreshToken);
                    res.cookie('accessToken', accessToken, { httpOnly: true })
                    res.cookie('refreshToken', refreshToken, { httpOnly: true })
                    res.send().status(200)
                } else {
                    res.status(400).json({ error: 'Invalid credentials' })
                }
            } else {
                res.status(400).json({ error: 'User does not exist' })
            }
        })

        app.post('/auth/token', (req, res) => {
            const refreshToken = req.body.token
            if (refreshToken == null) return res.sendStatus(401)
            if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
            jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
                if (err) return res.sendStatus(403)
                res.cookie('accessToken', this.generate_access_token({ name: user.name }), { httpOnly: true, overwrite: true })
            })
        })

        app.delete('/auth/logout', (req, res) => {
            if (req.body.token == null || undefined) {
                res.sendStatus(401);
            }
            refreshTokens = refreshTokens.filter(token => token !== req.body.token)
            res.sendStatus(204)
        })

        app.listen(this.options.port, () => {
            console.log(`Server started on port ${this.options.port}`);
        });

    }

    register_secure_pages (data) {
        for ( let i = 0; i < data.length; i++) {
            app.get(data[i].route, this.authenticate_token, (req, res) => {
                res.sendFile(data[i].fileLocation);
            });
        }
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
        //TODO: Implement this later
    }

    authenticate_token(req, res, next) {
        const token = req.body.accessToken;
        if (token == undefined || null) return res./*sendStatus(401).*/redirect('/login?redirect=' + req.originalUrl);
    
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                this.handle_error(err, "Failed to authenticate token");
                return res.sendStatus(403)
            }
            req.user = user;
            next();
        })
    }

    status() {
        return {
            Running: this.isRunning,
            AuthErrors: this.errors,
            DBErrors: this.DB.errors
        }
    }

    handle_error(error, message) {
        console.log(`
        | ${error} | 
        | ${message} |
        `);
        this.errors.push({error: error, message: message});
    }
}