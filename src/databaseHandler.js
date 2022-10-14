const mongo = require('mongodb').MongoClient;

//TODO: Change the .insertOne() to the non depreciated version to ensure the code doesn't break in the future when it is fully removed

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
    }

    add_user_to_db(username, password) {
        this.db.collection("users").insertOne({
            username: username,
            password: password,
        }, (err, res) => {
            if (err) {
                this.handle_error(err, "Failed to add user to database");
            }
        });
    }

    get_db_collections_length() {
        return this.db.listCollections().toArray((err, collections) => {
            if (err) {
                this.handle_error(err, "Failed to get collections");
            }
            return collections.length;
        });
    }

    check_user_in_database() {
        this.db.collection("users").find({}).toArray((err, res) => {
            if (err) {
                this.handle_error(err, "Failed to get user from database");
            }
            if (res.length == 0) {
                return false;
            } else {
                return true;
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