#!/bin/bash

cd "$(dirname "$0")"

echo "⚠️  WARNING: This will permanently delete all FASTT containers, images, and volumes!"
read -p "Are you sure you want to proceed? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "❌ Uninstallation canceled."
    exit 0
fi

echo "🛑 Stopping all FASTT containers..."
docker-compose down -v --rmi all

echo "🧹 Removing FASTT-related containers..."
docker rm -f FASTTAPP FASTTCELERY FASTTSERVER FASTTDB FASTTREDIS 2>/dev/null

echo "🧹 Removing FASTT-related images..."
docker rmi -f $(docker images -q 'fastt*') 2>/dev/null

echo "🧹 Removing FASTT volumes..."
docker volume rm mysql_data 2>/dev/null

echo "🧹 Cleaning up unused Docker resources..."
docker system prune -f

echo "✅ FASTT has been completely uninstalled."
