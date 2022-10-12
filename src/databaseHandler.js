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

    //TODO: Make this a universal function as it is used in multiple places and cannot access un-instantiated function from other classes
    handle_error(error, message) {
        console.log(`
        | ${error} | 
        | ${message} |
        `);
    }
}