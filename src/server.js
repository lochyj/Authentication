const Authentication = require("./authentication.js");

var Auth = new Authentication({
    port: "80"
})

Auth.register_secure_pages([
    {route:"/app", fileLocation:"./app.html"},
    {route:"/profile", fileLocation: "./profile.html"}
]);

Auth.start_server();

console.log(Auth.status());
