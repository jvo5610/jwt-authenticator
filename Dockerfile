# ──────────────────────────────
# 1️⃣ BUILD STAGE: Compile Binary
# ──────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive


# Install dependencies
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    ca-certificates \
    build-essential \
    cmake \
    curl \
    libcurl4-openssl-dev \
    libssl-dev \
    libmicrohttpd-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source files
COPY CMakeLists.txt . 
COPY src ./src

# Build the application
RUN cmake -B build -S . && cmake --build build --target all

# ──────────────────────────────
# 2️⃣ RUNTIME STAGE: Minimal Image with Compiled Binary
# ──────────────────────────────
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies (only what is needed)
RUN apt-get update && apt-get install -y \
    curl \
    libcurl4 \
    libssl3 \
    libmicrohttpd12 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the compiled binary from builder stage
COPY --from=builder /app/build/auth-server /app/auth-server

# Expose server port
EXPOSE 3000

# Run the application
CMD ["/app/auth-server"]