// Standard libraries
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <condition_variable>
#include <unordered_map>
#include <unistd.h>

// Third-party libraries
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <hv/HttpServer.h>

// Namespaces
using json = nlohmann::json;
using namespace std;

// =====================
// GLOBALS
// =====================

// Env vars
const string JWKS_URL = getenv("JWKS_URL");
const int JWKS_REFRESH_INTERVAL = getenv("JWKS_REFRESH_INTERVAL") 
    ? std::max(atoi(getenv("JWKS_REFRESH_INTERVAL")), 1) 
    : 600;
const int PORT = getenv("PORT") 
    ? std::max(atoi(getenv("PORT")), 1) 
    : 3000;

// Server status
std::atomic<bool> running(true);

// ========================
// SYNC AND STATUS
// ========================

std::mutex shutdown_mutex;
std::condition_variable shutdown_cv;

// JWT cache and locks
std::mutex jwks_mutex;
std::mutex jwks_map_mutex;
std::string jwks_cache;
std::time_t last_jwks_update = 0;

// Metrics validations
std::atomic<int> valid_requests(0);
std::atomic<int> invalid_requests(0);
std::atomic<int> jwt_validations_in_progress(0);
std::atomic<long> total_validation_time_ns(0);

// Cached keys structure
struct JwkEntry {
    json key;
    EVP_PKEY* public_key;
};
std::unordered_map<std::string, JwkEntry> jwks_map;

// ==================
// LOGS
// ==================

enum LogLevel { DEBUG, INFO, WARN, ERROR };
LogLevel current_log_level = ERROR; // Default to ERROR


void set_log_level()
{
    const char *env_log_level = getenv("LOG_LEVEL");
    if (env_log_level)
    {
        string level_str = env_log_level;
        if (level_str == "DEBUG")
            current_log_level = DEBUG;
        else if (level_str == "INFO")
            current_log_level = INFO;
        else if (level_str == "WARN")
            current_log_level = WARN;
        else if (level_str == "ERROR")
            current_log_level = ERROR;
    }
}

void log_message(LogLevel level, const string &message)
{
    if (level >= current_log_level)
    {
        string prefix;
        if (level == DEBUG)
            prefix = "[DEBUG] ";
        else if (level == INFO)
            prefix = "[INFO] ";
        else if (level == WARN)
            prefix = "[WARN] ";
        else if (level == ERROR)
            prefix = "[ERROR] ";
        cout << prefix << message << endl;
    }
}

// Function to fetch JWKS
size_t write_callback(void *contents, size_t size, size_t nmemb, string *output)
{
    output->append((char *)contents, size * nmemb);
    return size * nmemb;
}

string fetch_jwks()
{
    int attempts = 3;
    while (attempts-- > 0)
    {
        CURL *curl = curl_easy_init();
        string response;
        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, JWKS_URL.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            if (res == CURLE_OK && !response.empty()) {
                return response;
            } else {
                log_message(WARN, "Attempt to fetch JWKS failed. Retrying...");
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    log_message(ERROR, "Failed to fetch JWKS after 3 attempts.");
    return "";
}

// Convert PEM certificate to RSA Public Key
EVP_PKEY *convert_pem_to_evp(const string &pem_cert)
{
    BIO *bio = BIO_new_mem_buf(pem_cert.c_str(), -1);
    if (!bio) {
        log_message(ERROR, "BIO_new_mem_buf failed.");
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!x509) {
        log_message(ERROR, "PEM_read_bio_X509 failed: unable to parse certificate.");
        BIO_free(bio);
        return nullptr;
    }

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    if (!pkey) {
        log_message(ERROR, "X509_get_pubkey failed: could not extract public key.");
    }

    X509_free(x509);
    BIO_free(bio);
    return pkey;
}

// JWKS Cache Updater Thread
void jwks_updater() {
    {
        std::lock_guard<std::mutex> lock_jwks(jwks_mutex);
        jwks_cache = fetch_jwks();
        last_jwks_update = time(nullptr);

        if (!jwks_cache.empty()) {
            log_message(INFO, "Initial JWKS cache populated.");

            try {
                json parsed = json::parse(jwks_cache);
                std::lock_guard<std::mutex> lock_map(jwks_map_mutex);
                jwks_map.clear();

                for (const auto& key : parsed["keys"]) {
                    if (key.contains("kid") && key.contains("x5c") && !key["x5c"].empty()) {
                        string kid = key["kid"].get<string>();
                        string pem = "-----BEGIN CERTIFICATE-----\n" + key["x5c"][0].get<string>() + "\n-----END CERTIFICATE-----\n";
                        EVP_PKEY* pubkey = convert_pem_to_evp(pem);

                        if (pubkey) {
                            jwks_map[kid] = { key, pubkey };
                            log_message(DEBUG, "Initial JWKS added kid: " + kid);
                        } else {
                            log_message(WARN, "Failed to parse PEM for kid: " + kid);
                        }
                    }
                }

                log_message(INFO, "Initial JWKS map loaded with " + to_string(jwks_map.size()) + " keys.");
            } catch (const std::exception& e) {
                log_message(ERROR, string("Failed to parse initial JWKS: ") + e.what());
            }
        } else {
            log_message(ERROR, "Failed to fetch initial JWKS.");
        }
    }

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(JWKS_REFRESH_INTERVAL));
        std::lock_guard<std::mutex> lock_jwks(jwks_mutex);

        time_t now = time(nullptr);
        if (now - last_jwks_update < JWKS_REFRESH_INTERVAL) {
            log_message(DEBUG, "JWKS cache still valid, skipping update.");
            continue;
        }

        string new_jwks = fetch_jwks();
        if (!new_jwks.empty()) {
            try {
                json parsed = json::parse(new_jwks);
                std::lock_guard<std::mutex> lock_map(jwks_map_mutex);

                unordered_map<string, JwkEntry> updated_map;

                for (const auto& key : parsed["keys"]) {
                    if (!key.contains("kid") || !key.contains("x5c") || key["x5c"].empty())
                        continue;

                    string kid = key["kid"].get<string>();
                    string new_cert = key["x5c"][0].get<string>();
                    string pem = "-----BEGIN CERTIFICATE-----\n" + new_cert + "\n-----END CERTIFICATE-----\n";

                    auto it = jwks_map.find(kid);
                    if (it != jwks_map.end() && it->second.key["x5c"][0] == new_cert) {
                        // No change: reuse public keys
                        updated_map[kid] = it->second;
                        log_message(DEBUG, "JWKS unchanged for kid: " + kid);
                    } else {
                        // On change make update
                        EVP_PKEY* pubkey = convert_pem_to_evp(pem);
                        if (pubkey) {
                            updated_map[kid] = { key, pubkey };
                            log_message(DEBUG, "JWKS updated or added kid: " + kid);
                            if (it != jwks_map.end() && it->second.public_key) {
                                EVP_PKEY_free(it->second.public_key);
                            }
                        } else {
                            log_message(WARN, "Failed to parse PEM for kid: " + kid);
                        }
                    }
                }

                // Free unused keys
                for (const auto& [kid, entry] : jwks_map) {
                    if (updated_map.find(kid) == updated_map.end() && entry.public_key) {
                        EVP_PKEY_free(entry.public_key);
                        log_message(DEBUG, "Removed unused key for kid: " + kid);
                    }
                }

                jwks_map = std::move(updated_map);
                last_jwks_update = time(nullptr);
                log_message(INFO, "JWKS map updated with " + to_string(jwks_map.size()) + " keys.");
            } catch (const std::exception& e) {
                log_message(ERROR, string("Failed to parse new JWKS: ") + e.what());
            }
        } else {
            log_message(WARN, "JWKS update failed or empty.");
        }
    }
}

// Retrieve JWKS from cache
string get_cached_jwks()
{
    std::lock_guard<std::mutex> lock_jwks(jwks_mutex);
    return jwks_cache;
}

// Base64 URL decoding
string base64_url_decode(const string &input)
{
    try {
        string base64 = input;
        replace(base64.begin(), base64.end(), '-', '+');
        replace(base64.begin(), base64.end(), '_', '/');
        while (base64.size() % 4 != 0)
            base64 += '=';
        
        BIO *bio, *b64;
        int length = base64.size() * 3 / 4 + 1;
        vector<char> buffer(length);

        bio = BIO_new_mem_buf((void*)base64.data(), base64.size());
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        int decoded_length = BIO_read(bio, buffer.data(), length);
        BIO_free_all(bio);

        if (decoded_length <= 0) throw runtime_error("Failed to decode base64.");

        return string(buffer.data(), decoded_length);
    } catch (const exception& e) {
        log_message(WARN, string("Base64 decode failed: ") + e.what());
        return "";
    }
}

// Extract KID from JWT header
string extract_kid(const string &token)
{
    json header;
    size_t first_dot = token.find('.');
    if (first_dot == string::npos)
        return "";
    string header_b64 = token.substr(0, first_dot);
    string header_json = base64_url_decode(header_b64);

    try {
        header = json::parse(header_json);
    } catch (const std::exception &e) {
        log_message(WARN, string("Failed to parse JWT header JSON: ") + e.what());
        return "";
    }
    if (header["alg"] != "RS256") {
        log_message(WARN, "Unsupported JWT algorithm: " + header["alg"].get<string>());
        return "";
    }
    return header["kid"];
}

// Extract and validate expiration EXP
bool validate_expiration(const string &token)
{
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    if (second_dot == string::npos)
        return false;

    string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    string payload_json = base64_url_decode(payload_b64);

    json payload = json::parse(payload_json);
    if (!payload.contains("exp"))
        return false;

    time_t exp = payload["exp"];
    time_t now = time(nullptr);

    if (exp < now)
    {
        log_message(WARN, "Token has expired.");
        return false;
    }

    log_message(DEBUG, "Token is not expired.");
    return true;
}

// Function to retrieve cached key
EVP_PKEY* get_cached_pubkey(const std::string& kid)
{
    std::lock_guard<std::mutex> lock_map(jwks_map_mutex);
    if (jwks_map.count(kid)) {
        return jwks_map[kid].public_key;
    }
    log_message(WARN, "KID not found in JWKS map: " + kid);
    return nullptr;
}

// Verify JWT Signature
bool verify_signature(EVP_PKEY *public_key, const string &header_payload, const string &signature)
{
    thread_local EVP_MD_CTX *ctx = nullptr;

    if (!ctx) {
        ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
    } else {
        EVP_MD_CTX_reset(ctx);
    }

    EVP_PKEY_CTX *pkey_ctx = NULL;
    bool result = false;

    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, public_key) <= 0)
        return false;
    if (EVP_DigestVerifyUpdate(ctx, header_payload.c_str(), header_payload.size()) <= 0)
        return false;

    if (EVP_DigestVerifyFinal(ctx, (unsigned char *)signature.data(), signature.size()) == 1)
    {
        result = true;
    }

    return result;
}

// Verify JWT
bool verify_jwt(const std::string &token)
{
    struct TimerGuard {
        std::chrono::high_resolution_clock::time_point start;
        TimerGuard() {
            jwt_validations_in_progress++;
            start = std::chrono::high_resolution_clock::now();
        }
        ~TimerGuard() {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            total_validation_time_ns += duration_ns;
            jwt_validations_in_progress--;
        }
    } guard;

    try {
        log_message(DEBUG, "Starting JWT verification: prefix = " + token.substr(0, 20));

        // Step 1: expiration
        if (!validate_expiration(token)) {
            log_message(DEBUG, "JWT verification failed: expiration check.");
            return false;
        }

        // Step 2: split token
        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);
        if (first_dot == std::string::npos || second_dot == std::string::npos) {
            log_message(DEBUG, "JWT verification failed: token does not have correct JWT format.");
            return false;
        }

        std::string header_payload = token.substr(0, second_dot);
        std::string signature_b64 = token.substr(second_dot + 1);
        std::string signature = base64_url_decode(signature_b64);

        if (signature.empty()) {
            log_message(DEBUG, "JWT verification failed: signature part is empty or could not be decoded.");
            return false;
        }

        // Step 3: extract kid
        std::string kid = extract_kid(token);
        if (kid.empty()) {
            log_message(DEBUG, "JWT verification failed: unable to extract KID.");
            return false;
        }

        log_message(DEBUG, "JWT extracted KID: " + kid);

        // Step 4: get public key
        EVP_PKEY* public_key = get_cached_pubkey(kid);
        if (!public_key) {
            log_message(DEBUG, "JWT verification failed: no public key found for KID.");
            return false;
        }

        // Step 5: verify signature
        if (!verify_signature(public_key, header_payload, signature)) {
            log_message(DEBUG, "JWT verification failed: signature did not match.");
            return false;
        }

        log_message(DEBUG, "JWT successfully verified.");
        return true;
    }
    catch (const std::exception& e) {
        log_message(ERROR, std::string("JWT verification threw exception: ") + e.what());
        return false;
    }
    catch (...) {
        log_message(ERROR, "JWT verification threw unknown exception.");
        return false;
    }
}

// Start http server
void start_server() {
    log_message(INFO, "Starting server with libhv on port " + std::to_string(PORT));

    hv::HttpService router;

    router.GET("/metrics", [](HttpRequest* req, HttpResponse* resp) {
        std::string metrics =
            "jwt_auth_valid_requests " + std::to_string(valid_requests.load()) + "\n"
            "jwt_auth_invalid_requests " + std::to_string(invalid_requests.load()) + "\n"
            "jwt_auth_validation_in_progress " + std::to_string(jwt_validations_in_progress.load()) + "\n"
            "jwt_auth_validation_total_ns " + std::to_string(total_validation_time_ns.load()) + "\n"
            "jwt_auth_avg_validation_time_ns " +
            std::to_string(valid_requests.load() > 0
                ? total_validation_time_ns.load() / valid_requests.load()
                : 0) + "\n";

        resp->status_code = HTTP_STATUS_OK;
        return resp->String(metrics);
    });

    router.POST("/", [](HttpRequest* req, HttpResponse* resp) {
    std::string auth = req->GetHeader("Authorization");

    // Trim utility
    auto trim = [](std::string s) -> std::string {
        s.erase(0, s.find_first_not_of(" \t\r\n"));
        s.erase(s.find_last_not_of(" \t\r\n") + 1);
        return s;
    };

    auth = trim(auth);

    if (!auth.empty() && auth.rfind("Bearer ", 0) == 0) {
        std::string token = trim(auth.substr(7));

        if (verify_jwt(token)) {
            valid_requests++;
            resp->status_code = HTTP_STATUS_OK;
            resp->SetBody("JWT is valid.");
            log_message(INFO, "Valid JWT received");
            return -1;
        } else {
            invalid_requests++;
            resp->status_code = HTTP_STATUS_FORBIDDEN;
            resp->SetBody("JWT verification failed.");
            log_message(WARN, "JWT verification failed");
            return -1;
        }
    } else {
        resp->status_code = HTTP_STATUS_FORBIDDEN;
        resp->SetBody("Missing or invalid Authorization header.");
        log_message(WARN, "No valid Authorization header");
        return -1;
    }
});


    hv::HttpServer server;
    server.service = &router;
    server.port = PORT;
    unsigned int threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;
    server.setThreadNum(threads);

    if (server.start() != 0) {
        log_message(ERROR, "Failed to start HTTP server.");
        return;
    }

    std::unique_lock<std::mutex> lock(shutdown_mutex);
    shutdown_cv.wait(lock, [] { return !running.load(); });

    server.stop();
}

void signal_handler(int signum) {
    running = false;
    shutdown_cv.notify_all();  // Esta es la mejora
    log_message(INFO, "Received signal " + std::to_string(signum));
}

// Main function
int main() {
    set_log_level();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::thread jwks_thread(jwks_updater);  // sin while redundante

    start_server();  // espera hasta que se recibe señal y se desbloquea el shutdown

    if (jwks_thread.joinable()) {
        jwks_thread.join();
    }

    log_message(INFO, "Server shutdown complete.");
    return 0;
}

