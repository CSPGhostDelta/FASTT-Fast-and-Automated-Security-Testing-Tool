#!/bin/bash

cd "$(dirname "$0")"

echo "Installing FASTT..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker and try again."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
fi

echo "Building and starting FASTT containers..."
docker-compose up -d --build

echo "Waiting for containers to start..."
sleep 5

SERVER_CONTAINER="FASTTSERVER"
IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $SERVER_CONTAINER 2>/dev/null)

if [ -z "$IP_ADDRESS" ]; then
    echo "❌ Failed to retrieve the IP address of the FASTT application."
    echo "Check if the container '$SERVER_CONTAINER' is running with: docker ps -a"
    exit 1
else
    echo "✅ FASTT installation is complete."
    echo "The application is running at: http://$IP_ADDRESS"
fi