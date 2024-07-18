// Load environment variables from .env file if not in production
if (process.env.NODE_ENV !== "production"){
    require("dotenv").config()
}

// Import necessary modules
const express = require("express");
// For hashing passwords
const bcrypt = require('bcrypt'); 
// Passport configuration
const initializePassport = require("./passport-config"); 
// For authentication
const passport = require("passport"); 
// For flash messages
const flash = require("express-flash"); 
// For managing sessions
const session = require("express-session"); 
// For supporting HTTP methods like DELETE
const methodOverride = require("method-override") 
// Initialize express application
const app = express(); 
// Set port number
const port = 3000; 

// Initialize Passport.js for auth
initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id )
)

// Sample in-memory user storage
const users = [];

// Middleware to parse URL-encoded data from the form
app.use(express.urlencoded({ extended: false }));

// Middleware for flash messages
app.use(flash());

// Middleware to manage sessions
app.use(session({
    secret : process.env.SECRET_KEY, // Secret key for encrypting session data
    resave: false, // Do not save session if unmodified
    saveUninitialized: false // Do not create session until something stored
}));

// Initialize Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Middleware to override HTTP methods (e.g., to support DELETE)
app.use(methodOverride("_method"));

// Route to handle login form submission with Passport authentication
app.post("/login", checkNotauth, passport.authenticate("local",{
    successRedirect: "/", // Redirect on successful login
    failureRedirect: "/login", // Redirect on failed login
    failureFlash: true // Enable flash messages
}));

// Route to handle registration form submission
app.post("/register", checkNotauth, async (req, res) => {
    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(req.body.password, 10); 
        // Add new user to the in-memory users array
        users.push({
            id: Date.now().toString(), // Generate a unique ID based on current time
            name: req.body.fullname, // User's full name
            email: req.body.email, // User's email
            password: hashedPassword, // Hashed password
        });
        // Redirect to login page after successful registration
        res.redirect("/login");
    } catch (e) {
        console.log(e); 
        // Redirect to register page if an error occurs
        res.redirect("/register");
    }
    console.log(users);
});

// Middleware to check if user is authenticated
function checkauth(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

// Middleware to check if user is not authenticated
function checkNotauth(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/"); // Redirect to home if already authenticated
    }
    next(); // Proceed if not authenticated
}

// Routes
app.get("/", checkauth, (req, res) => {
    res.render("index.ejs"); // Render home page if authenticated
});

app.get("/login", checkNotauth, (req, res) => {
    res.render("login.ejs"); // Render login page if not authenticated
});

app.get("/register", checkNotauth, (req, res) => {
    res.render("register.ejs"); // Render register page if not authenticated
});

// Route to handle logout
app.delete("/logout", (req, res) => {
    req.logOut(req.user, err => { // Log out the user
        if (err) return next(err); // Handle errors
    });
    res.redirect('/login'); // Redirect to login page after logout
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
