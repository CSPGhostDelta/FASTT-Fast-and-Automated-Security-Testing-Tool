#!/bin/bash

# Navigate to the directory containing the docker-compose.yml file
cd "$(dirname "$0")"

# Stop all FastT containers
echo "Stopping FASTT containers..."
docker-compose stop

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "All FastT containers have been stopped."
else
    echo "Failed to stop FastT containers."
fi