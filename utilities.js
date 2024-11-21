const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    // Correct way to access the Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.sendStatus(401); // Unauthorized if no token is found

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden if token is invalid
        req.user = user; // Attach user info to request object
        next(); // Proceed to the next middleware
    });
}

module.exports = {
    authenticateToken,
};
