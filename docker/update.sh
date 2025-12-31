#!/bin/bash

cd "$(dirname "$0")"

cd ..

echo "--- Current directory: $(pwd) ---"

echo "--- 1. Pulling latest code from GitHub ---"
git pull origin main

echo "--- 2. Building and restarting containers ---"

if [ ! -f "docker/docker-compose.yml" ]; then
    echo "❌ CRITICAL ERROR: docker/docker-compose.yml not found in $(pwd)"
    exit 1
fi

if command -v docker-compose &> /dev/null
then
    docker-compose -f docker/docker-compose.yml up -d --build
else
    docker compose -f docker/docker-compose.yml up -d --build
fi

echo "--- 3. Cleanup unused images ---"
docker image prune -f

echo "✅ Production updated successfully!"