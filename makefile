# Variables
REPO ?= pepe5610/auth-server
TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64
AUTH0_DOMAIN ?=

# Default target
.PHONY: build push run clean

# Build the multi-arch Docker image

build:
	docker buildx build --load -t $(REPO):$(TAG) .

push:
	docker buildx build --platform $(PLATFORMS) -t $(REPO):$(TAG) --push .

# Run the container locally
run:
	@echo "Running container with AUTH0_DOMAIN=$(AUTH0_DOMAIN)"
	docker run -e LOG_LEVEL=DEBUG -e AUTH0_DOMAIN=$(AUTH0_DOMAIN) -p 3000:3000 $(REPO):$(TAG)

# Clean up Docker images
clean:
	docker rmi -f $(REPO):$(TAG)

# Show available architectures in the pushed image
inspect:
	docker manifest inspect $(REPO):$(TAG)

# Enable buildx (run once)
setup:
	docker buildx create --use
	docker buildx ls
	