# jwt-authenticator

A high-performance C++ server for verifying `RS256` JWT tokens using public keys from a JWKS endpoint. Designed for low latency, concurrency, and Prometheus-style metrics.

---

## 🚀 What It Does

- Exposes a lightweight HTTP server using [libhv](https://github.com/ithewei/libhv)
- Validates JWTs passed in the `Authorization: Bearer <token>` header
- Verifies:
  - Signature using the public key from JWKS (`x5c`)
  - Expiration time (`exp`)
  - Supported algorithm: `RS256`
- Caches JWKS and periodically refreshes it
- Exposes `/metrics` endpoint with Prometheus-compatible metrics

---

## 🧩 Environment Variables

| Variable                | Required | Default | Description |
|-------------------------|----------|---------|-------------|
| `JWKS_URL`              | ✅       | –       | URL to fetch the JWKS (JSON Web Key Set) |
| `JWKS_REFRESH_INTERVAL` | ❌       | `600`   | Interval in seconds to refresh JWKS (minimum: 1 second) |
| `PORT`                  | ❌       | `3000`  | Port where the server listens |
| `LOG_LEVEL`             | ❌       | `ERROR` | Logging level: `DEBUG`, `INFO`, `WARN`, or `ERROR` |

---

## 📈 Metrics

Exposed at `/metrics` in Prometheus format:

- `jwt_auth_valid_requests` – count of successful JWT validations  
- `jwt_auth_invalid_requests` – count of failed JWT validations  
- `jwt_auth_validation_in_progress` – active validations (concurrent)  
- `jwt_auth_validation_total_ns` – total validation time in nanoseconds  
- `jwt_auth_avg_validation_time_ns` – average time per validation (ns)  

Example:

```
jwt_auth_valid_requests 20000
jwt_auth_invalid_requests 0
jwt_auth_validation_in_progress 0
jwt_auth_validation_total_ns 3658934936
jwt_auth_avg_validation_time_ns 182946
```

---

## 🔧 Dependencies

| Library                     | Purpose |
|-----------------------------|---------|
| [libhv](https://github.com/ithewei/libhv)       | High-performance async HTTP server |
| [OpenSSL](https://www.openssl.org/)             | Public key handling and signature verification |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON parsing for JWKS and JWT |
| [libcurl](https://curl.se/libcurl/)             | Fetch JWKS from remote server |

---

## 🐳 Docker Usage

### Build the image

```bash
docker build -t auth-server .
```

### Run the container

```bash
docker run -p 3000:3000 \
  -e JWKS_URL=https://example.com/.well-known/jwks.json \
  -e JWKS_REFRESH_INTERVAL=300 \
  -e LOG_LEVEL=INFO \
  auth-server
```

---

## 🔍 Endpoints

### `/`  
**Method:** `GET`  
**Header:** `Authorization: Bearer <jwt>`

- `200 OK` – JWT is valid
- `403 Forbidden` – JWT is missing, expired, or invalid

---

### `/metrics`  
**Method:** `GET`

Returns Prometheus-style metrics.

---

## 🛑 Graceful Shutdown

- The server handles `SIGINT` and `SIGTERM` for graceful shutdown
- Background threads (e.g., JWKS refresher) are properly joined and stopped

---

## 📄 License

Apache License