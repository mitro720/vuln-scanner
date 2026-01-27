import { useEffect, useRef, useState } from 'react'
import { io } from 'socket.io-client'

const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:3000'

export const useWebSocket = (scanId) => {
    const [isConnected, setIsConnected] = useState(false)
    const [scanData, setScanData] = useState(null)
    const [progress, setProgress] = useState(0)
    const [findings, setFindings] = useState([])
    const socketRef = useRef(null)

    useEffect(() => {
        if (!scanId) return

        // Create socket connection
        socketRef.current = io(WS_URL)

        socketRef.current.on('connect', () => {
            console.log('WebSocket connected')
            setIsConnected(true)

            // Subscribe to scan updates
            socketRef.current.emit('subscribe', scanId)
        })

        socketRef.current.on('disconnect', () => {
            console.log('WebSocket disconnected')
            setIsConnected(false)
        })

        socketRef.current.on('subscribed', (data) => {
            console.log('Subscribed to scan:', data.scanId)
        })

        // Scan event handlers
        socketRef.current.on('scan:started', (data) => {
            console.log('Scan started:', data)
            setScanData(data)
        })

        socketRef.current.on('scan:progress', (data) => {
            console.log('Scan progress:', data)
            setProgress(data.progress || 0)
            setScanData((prev) => ({ ...prev, ...data }))
        })

        socketRef.current.on('scan:finding', (data) => {
            console.log('New finding:', data.finding)
            setFindings((prev) => [...prev, data.finding])
        })

        socketRef.current.on('scan:completed', (data) => {
            console.log('Scan completed:', data)
            setScanData((prev) => ({ ...prev, ...data, status: 'completed' }))
            setProgress(100)
        })

        socketRef.current.on('scan:error', (data) => {
            console.error('Scan error:', data.error)
            setScanData((prev) => ({ ...prev, ...data, status: 'failed' }))
        })

        // Cleanup
        return () => {
            if (socketRef.current) {
                socketRef.current.emit('unsubscribe', scanId)
                socketRef.current.disconnect()
            }
        }
    }, [scanId])

    return {
        isConnected,
        scanData,
        progress,
        findings,
    }
}
