import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'securescan-secret-key-123'

export const protect = (req, res, next) => {
    let token

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1]
    }

    // Bypass for internal python scanner
    const scannerKey = process.env.SCANNER_API_KEY || 'secure-scanner-key'
    if (req.headers['x-scanner-api-key'] === scannerKey) {
        req.user = { id: 'system', role: 'admin' }
        return next()
    }

    if (!token) {
        return res.status(401).json({ error: 'Not authorized to access this route' })
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET)
        req.user = decoded
        next()
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' })
    }
}

export const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'User role not authorized for this action' })
        }
        next()
    }
}
