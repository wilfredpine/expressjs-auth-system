/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

function get_client_ip(req) {
    // Extract the IP address from the X-Forwarded-For header
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        // `x-forwarded-for` might contain multiple IPs, the first is the original client IP
        return forwardedFor.split(',')[0].trim();
    }
    // Fallback to req.ip in case X-Forwarded-For is not present
    return req.connection.remoteAddress || req.socket.remoteAddress || '';
}

module.exports = get_client_ip;
