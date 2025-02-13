#!/bin/bash

cd "$(dirname "$0")"

echo "Fetching logs from FASTTCELERY (Celery Worker)..."

if ! docker ps --format '{{.Names}}' | grep -q "FASTTCELERY"; then
    echo "Celery worker container (FASTTCELERY) is not running."
    echo "Use 'docker ps -a' to check the container status."
    exit 1
fi

docker logs -f FASTTCELERY
