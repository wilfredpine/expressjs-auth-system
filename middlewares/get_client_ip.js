/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

/**
 * Get client IP Address
 * @param {*} req 
 * @returns 
 */
function get_client_ip(req) {
    
    const forwardedFor = req.headers['x-forwarded-for'];                        // Extract the IP address from the X-Forwarded-For header

    if (forwardedFor) {
        return forwardedFor.split(',')[0].trim();                               // `x-forwarded-for` might contain multiple IPs, the first is the original client IP
    }
    return req.connection.remoteAddress || req.socket.remoteAddress || '';      // Fallback to req.ip in case X-Forwarded-For is not present
}

module.exports = get_client_ip;
