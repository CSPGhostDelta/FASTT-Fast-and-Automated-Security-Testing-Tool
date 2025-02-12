#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Docker is installed
if command_exists docker; then
    echo "Docker is already installed."
else
    echo "Docker is not installed. Installing Docker..."

    # Update the package index
    sudo apt-get update

    # Install required packages
    sudo apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        software-properties-common

    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

    # Add the Docker APT repository
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

    # Update the package index again
    sudo apt-get update

    # Install Docker
    sudo apt-get install -y docker-ce

    # Start and enable Docker service
    sudo systemctl start docker
    sudo systemctl enable docker

    echo "Docker has been installed successfully."
fi

# Check if Docker Compose is installed
if command_exists docker-compose; then
    echo "Docker Compose is already installed."
else
    echo "Docker Compose is not installed. Installing Docker Compose..."

    # Download the latest version of Docker Compose
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

    # Apply executable permissions to the binary
    sudo chmod +x /usr/local/bin/docker-compose

    echo "Docker Compose has been installed successfully."
fi

# Verify installations
echo "Verifying installations..."
docker --version
docker-compose --version

# Build and start the containers
echo "Building and starting the Docker containers..."
docker-compose up --build -d

# Wait for a few seconds to allow the containers to start
sleep 5

# Get the IP address of the FastT application container
IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' FASTTSERVER)

# Check if the IP address was retrieved successfully
if [ -z "$IP_ADDRESS" ]; then
    echo "Failed to retrieve the IP address of the FASTT application."
else
    echo "All containers are up and running."
    echo "The application is running at http://$IP_ADDRESS"
fi