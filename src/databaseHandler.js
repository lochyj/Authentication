const mongo = require('mongodb').MongoClient;

//TODO: Change the .insertOne() to the non depreciated version to ensure the code doesn't break in the future when it is fully removed
//TODO: USE PROMISES! This is required as the auth system wont wait for the db to respond before continuing, causing the user to not be created or accessed.
module.exports = class DatabaseHandler {
    constructor (options) {
        this.options = options;
        mongo.connect(this.options.mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true }, (err, client) => {
            if (err) {
                this.handle_error(err, "Failed to connect to MongoDB");
            }
            this.db = client.db(this.options.DBName);
        });

        this.errors = [];

        console.log("DatabaseHandler - Connected to the database at: " + this.options.mongoUrl);
    }

    add_user_to_db(username, password) {
        this.db.collection("users").insertOne({
            username: username,
            password: password,
            firstLogin: new Date().getTime(),
            lastLogin: new Date().getTime()
        }, (err, res) => {
            if (err) {
                this.handle_error(err, "Failed to add user to database");
            }
        });
    }

    update_user_login_time(username) {
        this.db.collection("users").updateOne({username: username}, {$set: {lastLogin: new Date().getTime()}}, (err, res) => {
            if (err) {
                this.handle_error(err, "Failed to update user login time");
            }
        });
    }

    get_user_login_data(username) {
        var result = undefined;
        this.db.collection("users").find({username: username}).toArray((err, res) => {
            if (err) {
                this.handle_error(err, "Failed to get user data from database");
            }
            result = res;
        });
        return result;
    }

    get_db_collections_length() {
        return this.db.listCollections().toArray((err, collections) => {
            if (err) {
                this.handle_error(err, "Failed to get collections");
            }
            return collections.length;
        });
    }

    update_tokens_list(token) {
        this.db.collection("tokens").insertOne({token: token}, (err, res) => {
            if (err) {
                this.handle_error(err, "Failed to update tokens list");
            }
        });
    }

    check_user_in_database(username) {
        const promise = new Promise((resolve, reject) => {
            if (reject) this.handle_error(reject, "check_user_in_database promise rejected");
            resolve(this.db.collection("users").find({username: username}).toArray((err, res) => {
                if (err) this.handle_error(err, "Failed to get user from database");
            }));
        });
        promise.then ((result) => {
            if (result == 0) {
                return false;
            } else if (result > 0) {
                return true;
            } else {
                this.handle_error("Unknown error", "Failed to check if user is in database");
                return undefined;
            }
        });
    }

    init_db() {
        if (this.get_db_collections_length() == 0) {
            this.db.createCollection("users", (err, res) => {
                if (err) {
                    this.handle_error(err, "Failed to create collection 'users'");
                    return 1;
                }
            });
            this.db.createCollection("userData", (err, res) => {
                if (err) {
                    this.handle_error(err, "Failed to create collection 'userData'");
                    return 1;
                }
            });
            return 0;
        }
    }

    return_errors() {
        return this.errors;
    }

    //TODO: Make this a universal function as it is used in multiple places and cannot access un-instantiated function from other classes
    handle_error(error, message) {
        console.log(`
        | ${error} | 
        | ${message} |
        `);
        this.errors.push({error: error, message: message});
    }
}