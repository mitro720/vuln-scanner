#!/bin/bash
# Vulnerability Scanner - Docker Startup Script

echo "========================================"
echo "  Vulnerability Scanner (Docker Mode)   "
echo "========================================"
echo ""

# Check if docker is installed
if ! command -v docker &> /dev/null
then
    echo "[ERROR] Docker is not installed or not in PATH!"
    echo "Please install Docker from https://docs.docker.com/get-docker/"
    exit 1
fi

echo "Stopping any existing containers..."
docker-compose down

echo ""
echo "Building and starting all services (this may take a few minutes for the first time building Go tools)..."
docker-compose up --build -d

echo ""
echo "========================================"
echo "  All Services Starting!                "
echo "========================================"
echo ""
echo "Please allow a minute or two for the services to fully initialize."
echo ""
echo "Backend API: http://localhost:5000/api"
echo "Frontend UI: http://localhost:5173"
echo "Scanner API: http://localhost:8000"
echo ""
echo "To view logs, run: docker-compose logs -f"
echo ""
