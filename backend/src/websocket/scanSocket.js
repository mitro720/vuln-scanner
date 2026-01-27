export const setupWebSocket = (io) => {
    io.on('connection', (socket) => {
        console.log('Client connected:', socket.id)

        // Subscribe to scan updates
        socket.on('subscribe', (scanId) => {
            console.log(`Client ${socket.id} subscribed to scan ${scanId}`)
            socket.join(`scan:${scanId}`)

            socket.emit('subscribed', { scanId })
        })

        // Unsubscribe from scan updates
        socket.on('unsubscribe', (scanId) => {
            console.log(`Client ${socket.id} unsubscribed from scan ${scanId}`)
            socket.leave(`scan:${scanId}`)
        })

        socket.on('disconnect', () => {
            console.log('Client disconnected:', socket.id)
        })
    })

    return {
        // Emit scan started event
        emitScanStarted: (scanId, data) => {
            io.to(`scan:${scanId}`).emit('scan:started', {
                scanId,
                timestamp: new Date().toISOString(),
                ...data,
            })
        },

        // Emit scan progress update
        emitScanProgress: (scanId, data) => {
            io.to(`scan:${scanId}`).emit('scan:progress', {
                scanId,
                timestamp: new Date().toISOString(),
                ...data,
            })
        },

        // Emit new finding
        emitFinding: (scanId, finding) => {
            io.to(`scan:${scanId}`).emit('scan:finding', {
                scanId,
                timestamp: new Date().toISOString(),
                finding,
            })
        },

        // Emit scan completed
        emitScanCompleted: (scanId, summary) => {
            io.to(`scan:${scanId}`).emit('scan:completed', {
                scanId,
                timestamp: new Date().toISOString(),
                summary,
            })
        },

        // Emit scan error
        emitScanError: (scanId, error) => {
            io.to(`scan:${scanId}`).emit('scan:error', {
                scanId,
                timestamp: new Date().toISOString(),
                error,
            })
        },
    }
}
