# ──────────────────────────────
# BUILD STAGE: Compile Binary
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
    git \
    libcurl4-openssl-dev \
    libssl-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

# Build libhv
RUN git clone --branch v1.3.3 https://github.com/ithewei/libhv.git /tmp/libhv && \
    cd /tmp/libhv && mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON .. && make -j$(nproc) && make install && \
    ldconfig && \
    rm -rf /tmp/libhv

# Set working directory
WORKDIR /app

# Copy source files
COPY CMakeLists.txt . 
COPY src ./src

# Build app
RUN cmake -B build -S . && cmake --build build --target all

# ──────────────────────────────
# RUNTIME STAGE: Minimal Image with Compiled Binary
# ──────────────────────────────
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies 
RUN apt-get update && apt-get install -y \
    curl \
    libcurl4 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Add libhv runtime dependency
COPY --from=builder /usr/local/lib/libhv.so /usr/local/lib/libhv.so
COPY --from=builder /usr/local/lib/ /usr/local/lib/

# Refresh ld cache
RUN ldconfig

# Set working directory
WORKDIR /app

# Copy the compiled binary from builder stage
COPY --from=builder /app/build/auth-server /app/auth-server

# Expose server port
EXPOSE 3000

# Run app
CMD ["/app/auth-server"]
