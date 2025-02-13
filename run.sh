#!/bin/bash

cd "$(dirname "$0")"

echo "Starting FASTT containers..."
docker-compose up -d

echo "Waiting for containers to start..."
sleep 5

SERVER_CONTAINER="FASTTSERVER"
IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $SERVER_CONTAINER 2>/dev/null)

if [ -z "$IP_ADDRESS" ]; then
    echo "❌ Failed to retrieve the IP address of the FASTT application."
    echo "🔍 Check if the container '$SERVER_CONTAINER' is running with: docker ps -a"
    exit 1
else
    echo "All FASTT containers are up and running."
    echo "The application is running at: http://$IP_ADDRESS"
fi
