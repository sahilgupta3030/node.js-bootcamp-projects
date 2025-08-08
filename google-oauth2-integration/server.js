const fs = require('fs'); // to read ssl certificate and key files
const path = require('path'); // to handle file paths easily
const https = require('https'); // to create https server
const express = require('express'); // express web framework
const helmet = require('helmet'); // helps secure app by setting http headers
const PORT = 3000;

// authentication related imports
const passport = require('passport'); // main passport package
const { Strategy } = require('passport-google-oauth20'); // google oauth strategy
const session = require('express-session'); // to handle sessions


/**
 * PART 0001
 * These are needed for Google login and secure cookie-based sessions.
 *
 * ➤ CLIENT_ID
 *    - Your Google app’s public ID
 *    - Used by Google to recognize which app is making the login request
 *    - You get this from Google Developer Console
 *
 * ➤ CLIENT_SECRET
 *    - A secret password given by Google
 *    - Used to verify that the request is actually coming from your app
 *    - Also generated from Google Developer Console
 *
 * HOW TO GET CLIENT_ID & CLIENT_SECRET:
 *    1. Go to https://console.cloud.google.com/
 *    2. Navigate to: APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID
 *    3. Choose "Web Application"
 *    4. Add redirect URI: https://localhost:3000/auth/google/callback
 *    5. After creating, you'll get both the ID and the secret
 *
 * ➤ COOKIE_KEY_001 & COOKIE_KEY_002
 *    - These are secret keys used to sign and protect session cookies
 *    - Two keys allow better security using key rotation
 *
 * Note: Cookie keys act like passwords — they ensure cookies can’t be tampered with
 */
const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_001: process.env.COOKIE_KEY_001,
  COOKIE_KEY_002: process.env.COOKIE_KEY_002,
}

/**
 * Google login config
 * - Must match callbackURL with Google Console
 */
const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback', // This must match redirect URI in Google Console
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};



/**
 * PART 0002
 * This function runs *after* Google verifies the user login.
 *
 * ➤ accessToken
 *    - A token that can be used to access the user's Google account info (like Google Drive, Gmail etc.)
 *    - We are not using it here, but it's available if needed
 *
 * ➤ refreshToken
 *    - Used to get a new accessToken when the old one expires
 *    - Not used in this basic example
 *
 * ➤ profile
 *    - Google sends back user details like email, name, ID, photo, etc.
 *    - This is where you usually save/check user in your database
 *
 * ➤ done()
 *    - This tells Passport that the login is done
 *    - Pass user data forward (we're just passing profile.id for now)
 */
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google Profile:', profile); // For debugging: see what data Google sends
  done(null, profile); // Pass the profile forward (you can trim or customize this)
}

/**
 * Initialize (setup) Passport with the Google OAuth strategy
 * Tell Passport to use Google strategy with our config and callback handler
 */
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));



/**
 * PART 0003
 * Runs right after successful login (after verifyCallback) and saves userId into session cookie
 * Save the session (userId) to the cookie OR serialize user information into the session
 * ➤ Saves userId into the session cookie for future requests
 */
passport.serializeUser((user, done) => {
  done(null, user.id); // Store the user ID in the session
  // You can also store the entire user object if needed, but it's better to store only the ID for security reasons
});

/**
 * Runs on every request that comes with a session cookie
 * Read the session (userId) from the cookie OR deserialize user information from the session
 * This lets Passport know the user is already logged in and trusted
 */
passport.deserializeUser((id, done) => {
  // // This is where you would retrieve the user from the database using the ID stored in the session
  // User.findById(id).then((user) => {
  //   done(null, user); // Pass the user object to the next middleware
  // });
  done(null, id); // For now, we will just return the ID as the user object
});



const app = express();

/**
 * PART 0004
 * Add basic security Headers using Helmet
 * Helps prevent common attacks like XSS, clickjacking, etc.
 *
 * Tailwind CDN requires relaxed CSP rules:
 * - Allow scripts/styles from cdn.tailwindcss.com
 * - Allow inline styles for Tailwind to work
 */
// app.use(helmet());
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
        styleSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
      },
    },
  })
);



/**
 * PART 0005
 * Configure session middleware for passport
 * ➤ Stores login session on the server
 * ➤ Signs session cookies with secret keys
 */
app.use(session({
  secret: [config.COOKIE_KEY_001, config.COOKIE_KEY_002], // array of secrets for extra security
  resave: false, // don't save session if nothing changes
  saveUninitialized: true, // create session even if not modified
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // Session cookie valid for 24 hours
    secure: true, // Send cookie only over HTTPS
  }
}));



// Initialize Passport for login/authentication system
app.use(passport.initialize());

/**
 * PART 0006
 * Enable session support in Passport (must come after express-session)
 * ➤ Reads session from cookie
 * ➤ Runs deserializeUser() to attach user to req.user
 */
app.use(passport.session());



/**
 * PART 0007
 * Middleware to protect private routes
 * It uses passport's built-in `req.isAuthenticated()` method
 * which returns true if the user is logged in and session is active
 * ➤ Checks if user is logged in using Passport
 * ➤ If not logged in, responds with 401 Unauthorized
 * ➤ If logged in, continues to next route handler
 */
function checkLoggedIn(req, res, next) {
  console.log('current user id is:', req.user);

  const isLoggedIn = req.isAuthenticated() && req.user;

  if (!isLoggedIn) {
    // return res.status(401).json({
    //   error: 'you must log in..',
    // });
    return res.status(401).send(`
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Unauthorized</title>
          <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-red-50 min-h-screen flex items-center justify-center">
          <div class="bg-white border border-red-200 rounded-3xl shadow-xl p-8 max-w-md w-full text-center space-y-4">
            <h1 class="text-2xl font-bold text-red-600">ACCESS DENIED 🚫</h1>
            <p class="text-gray-700 text-base">
              You must be logged in to view this page.
            </p>
            <a
              href="/auth/google"
              class="inline-block bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-5 rounded-full transition"
            >
              Login with Google
            </a>
          </div>
        </body>
      </html>
`);

  }
  next(); // user is authenticated, proceed
}



/**
 * PART 0008
 * This is where you would initiate the Google OAuth login
 * Redirects user to Google login page with requested scopes
 * Step 1: Start Google OAuth login
 */
app.get('/auth/google', passport.authenticate('google', {
  scope: ['email'], // Specify the scopes you want to access (can also include 'profile')
}));

/**
 * Step 2: Handle Google callback (after user logs in)
 * This is where you would handle the callback from Google after authentication
 * redirect based on success or failure
 */
app.get('/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/', // go to home on success
    failureRedirect: '/failure', // go to failure page on error
    // session: false,
  }),
  (req, res) => {
    // This is where you would handle the successful authentication
    // For now, we will just send a success message
    console.log('Google called back with user profile:', req.user);
    return res.status(200).json({
      message: 'Authentication successful! You can now access the secret route.'
    });
  }
);

/**
 * Step 3: Handle login failure
 * Called if authentication fails or is denied
 */
app.get('/failure', (req, res) => {
  return res.status(401).json({
    error: 'Authentication failed. Please try again.'
  });
});

/**
 * Step 4: Logout and destroy session
 * Logs the user out, destroys session, and clears cookie
 */
app.get('/auth/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.session.destroy(() => {
      res.clearCookie('connect.sid'); // Clear session cookie!
      res.redirect('/'); // Redirect to the home page after logout
      console.log('User logged out successfully.');
    });
  });
});



/**
 * PART 0009
 * Secret route → Protected page that needs login
 * Uses `checkLoggedIn` middleware to allow only logged-in users
 */
app.get('/secret', checkLoggedIn, (req, res) => {
  // return res.send('This is a secret message! Keep it safe!');
  return res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Secret Message</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gradient-to-br from-purple-100 to-blue-100 min-h-screen flex items-center justify-center">
        <div class="bg-white shadow-2xl rounded-3xl p-10 max-w-md w-full text-center border border-gray-200">
          <h1 class="text-2xl font-bold text-gray-800 mb-4">ACCESS GRANTED</h1>
          <p class="text-gray-600 text-lg">
            This is a <span class="font-semibold text-purple-600">secret message</span>!<br />
            Keep it safe and don’t share it!
          </p>
          <div class="mt-6">
            <a href="/" class="inline-block bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-5 rounded-full transition">
              Go to Home
            </a>
          </div>
        </div>
      </body>
    </html>
  `);
});

/**
 * Home route → Just serves the homepage (index.html)
 */
app.get('/', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});



/**
 * PART 00010
 * Using self-signed SSL certificate (key.pem & cert.pem) from /secrets folder for HTTPS
 * Required for secure cookies and Google OAuth redirect
 */
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'secrets', 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'secrets', 'cert.pem')),
};

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`Server is running on https://localhost:${PORT}`);
  console.log('Visit https://localhost:3000/secret to see the secret message.');
});


// GENERATING SSL CERTIFICATE AND KEY
// This section explains how to generate a self-signed SSL certificate and key
// for local development purposes. It is important to use HTTPS for secure communication,
// especially when dealing with authentication and sensitive data.
// NOTE: This is for local development only. In production, you should use a valid SSL certificate
// from a trusted Certificate Authority (CA).
// Generating a self-signed SSL certificate and key is essential for local development
// to ensure secure communication over HTTPS. This is particularly important when
// dealing with authentication flows, such as OAuth, where sensitive data is exchanged.
//
// The following code sets up an Express server with HTTPS support, using a self-signed certificate.
// To generate the SSL certificate and key, you can use the following command:
// Make sure you have OpenSSL installed on your system.
// Command to generate a self-signed certificate and key:
// This command will create a self-signed certificate valid for 365 days.
// IN TERMINAL: //  openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
// You will be prompted to enter some information for the certificate.
// Make sure to run this command in the same directory as your server.js file.
// After running the command, you will have two files: key.pem and cert.pem
// Make sure to keep these files secure and do not expose them publicly.
// NOTE: If you are using a self-signed certificate, your browser will show a warning.
// You can proceed by accepting the risk to view the secret message.
