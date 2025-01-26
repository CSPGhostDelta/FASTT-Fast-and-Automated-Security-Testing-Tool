#!/bin/bash

# Navigate to the directory containing the docker-compose.yml file
cd "$(dirname "$0")"

# Start the containers without rebuilding
echo "Starting FastT containers..."
docker-compose up -d

# Wait for a few seconds to allow the containers to start
sleep 5

# Get the IP address of the FastT application container
IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' FASTTAPP)

# Check if the IP address was retrieved successfully
if [ -z "$IP_ADDRESS" ]; then
    echo "Failed to retrieve the IP address of the FastT application."
else
    echo "All FastT containers are up and running."
    echo "The application is running at http://$IP_ADDRESS:5000"
fi