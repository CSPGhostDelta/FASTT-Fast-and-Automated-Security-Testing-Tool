#!/bin/bash

cd "$(dirname "$0")"

echo "Starting FASTT containers..."
docker-compose up -d
sleep 5

IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' FASTTSERVER)

# Check if the IP address was retrieved successfully
if [ -z "$IP_ADDRESS" ]; then
    echo "Failed to retrieve the IP address of the FASTT application."
else
    echo "All FASTT containers are up and running."
    echo "The application is running at http://$IP_ADDRESS"
fi