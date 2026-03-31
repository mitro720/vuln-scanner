import rateLimit from 'express-rate-limit'

// General API limiter — generous for a local dev/self-hosted tool
export const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 2000,  // raised from 100
    message: { success: false, error: 'Too many requests, please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip rate limiting for scan status / findings polling (high-frequency reads)
    skip: (req) => {
        const path = req.path
        const method = req.method
        // Allow unlimited GET polling on scan status and findings
        if (method === 'GET' && (
            /^\/scans\/[^/]+$/.test(path) ||
            /^\/scans\/[^/]+\/findings$/.test(path) ||
            /^\/scans\/[^/]+\/progress$/.test(path)
        )) return true
        return false
    },
})

// Scan creation limiter — keep strict (prevent abuse)
export const scanLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 hour
    max: 30,                     // 30 scans per hour
    message: { success: false, error: 'Too many scan requests. Please wait before starting another.' },
    standardHeaders: true,
    legacyHeaders: false,
})
