const Authentication = require("./authentication.js");

var Auth = new Authentication({
    port: "80"
})

Auth.register_secure_pages([
    {route:"/app", fileLocation:"./pages/secure/app.html"},
    {route:"/profile", fileLocation: "./pages/secure/profile.html"}
]);

Auth.register_pages([
    {route:"/login", fileLocation:"./pages/login.html"},
    {route:"/register", fileLocation: "./pages/register.html"}
]);


Auth.start_server();
