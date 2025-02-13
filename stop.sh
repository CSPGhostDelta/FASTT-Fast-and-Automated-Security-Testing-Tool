#!/bin/bash

cd "$(dirname "$0")"

echo "Stopping all FASTT containers..."
docker-compose down

echo "✅ All FASTT containers have been stopped."
