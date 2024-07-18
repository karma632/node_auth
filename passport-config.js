// Import necessary modules
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

function initialize(passport, getUserByEmail, getUserById) {
    // Function to authenticate users
    const authUsers = async (email, password, done) => {
        // Get user by email
        const user = getUserByEmail(email);
        if (user == null) {
            // If user not found, return an error message
            return done(null, false, { message: "No user found with that email" });
        }
        try {
            // Compare provided password with stored hashed password
            if (await bcrypt.compare(password, user.password)) {
                // If passwords match, authentication is successful
                return done(null, user);
            } else {
                // If passwords do not match, return an error message
                return done(null, false, { message: "Password incorrect" });
            }
        } catch (error) {
            // Handle errors during password comparison
            return done(error);
        }
    }

    // Configure Passport to use the local strategy for authentication
    passport.use(new LocalStrategy({ usernameField: 'email' }, authUsers));
    
    // Store user information into the session
    passport.serializeUser((user, done) => done(null, user.id));
    
    // Deserialize user information from the session : it refers to converting the stored user ID back into the full user object.
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id));
    });
}

// Export the initialize function
module.exports = initialize;
