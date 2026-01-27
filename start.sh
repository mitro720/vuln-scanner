#!/bin/bash
# Vulnerability Scanner - Linux/Mac Startup Script
# This script starts all components in parallel

echo "========================================"
echo "  Vulnerability Scanner - Starting"
echo "========================================"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js is not installed!"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python is not installed!"
    echo "Please install Python from https://www.python.org/"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "========================================"
    echo "  Stopping all services..."
    echo "========================================"
    kill $(jobs -p) 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[1/3] Starting Backend Server (Node.js)..."
cd backend && npm run dev &
BACKEND_PID=$!
sleep 2

echo "[2/3] Starting Frontend (React + Vite)..."
cd ../frontend && npm run dev &
FRONTEND_PID=$!
sleep 2

echo "[3/3] Starting Python Scanner Engine..."
cd ../scanner-core && python3 api_bridge.py &
SCANNER_PID=$!
sleep 2

echo ""
echo "========================================"
echo "  All Services Started!"
echo "========================================"
echo ""
echo "Backend:  http://localhost:5000"
echo "Frontend: http://localhost:5173"
echo "Scanner:  http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop all services..."

# Wait for all background processes
wait
