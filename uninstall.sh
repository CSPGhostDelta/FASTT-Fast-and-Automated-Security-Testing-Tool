#!/bin/bash

cd "$(dirname "$0")"

echo "Stopping and removing FASTTT containers..."
docker-compose down

if [ $? -eq 0 ]; then
    echo "All FASTT containers have been stopped and removed."
else
    echo "Failed to stop and remove FASTT containers."
fi