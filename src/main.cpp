#include <iostream>
#include <string>
#include <vector>
#include <curl/curl.h>
#include <ctime>
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <microhttpd.h>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>

using json = nlohmann::json;
using namespace std;

// Globals
std::mutex jwks_mutex;
std::string jwks_cache;
std::time_t last_jwks_update = 0;
const int PORT = 3000;
const int JWKS_REFRESH_INTERVAL = 600; // Refresh every 5 minutes
const string JWKS_URL = getenv("JWKS_URL");

// Global variables
std::atomic<bool> running(true);
struct MHD_Daemon *http_daemon = nullptr;

// Logging levels
enum LogLevel
{
    DEBUG,
    INFO,
    WARN,
    ERROR
};
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
    CURL *curl = curl_easy_init();
    string response;
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, JWKS_URL.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

// Signal handler function
void signal_handler(int signum)
{
    log_message(INFO, "Received termination signal. Shutting down...");
    running = false;
}

// JWKS Cache Updater Thread
void jwks_updater() {
    {
        // ✅ Perform initial JWKS fetch at startup
        std::lock_guard<std::mutex> lock(jwks_mutex);
        jwks_cache = fetch_jwks();
        last_jwks_update = time(nullptr);

        if (!jwks_cache.empty()) {
            log_message(INFO, "Initial JWKS cache populated.");
        } else {
            log_message(ERROR, "Failed to fetch initial JWKS.");
        }
    }

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(JWKS_REFRESH_INTERVAL)); // Wait before checking

        std::lock_guard<std::mutex> lock(jwks_mutex);

        time_t now = time(nullptr);
        if (now - last_jwks_update < JWKS_REFRESH_INTERVAL) {
            log_message(DEBUG, "JWKS cache still valid, skipping update.");
            continue;
        }

        string new_jwks = fetch_jwks();
        if (!new_jwks.empty() && new_jwks != jwks_cache) {
            jwks_cache = new_jwks;
            last_jwks_update = now;
            log_message(INFO, "JWKS cache updated.");
        } else {
            log_message(DEBUG, "JWKS unchanged, skipping update.");
        }
    }
}

// Function to retrieve JWKS from cache
string get_cached_jwks()
{
    std::lock_guard<std::mutex> lock(jwks_mutex);
    return jwks_cache;
}

// Base64 URL decoding
string base64_url_decode(const string &input)
{
    string base64 = input;
    replace(base64.begin(), base64.end(), '-', '+');
    replace(base64.begin(), base64.end(), '_', '/');
    while (base64.size() % 4 != 0)
        base64 += '=';

    BIO *bio, *b64;
    int length = base64.size() * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(length);

    bio = BIO_new_mem_buf(base64.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int decoded_length = BIO_read(bio, buffer, length);
    BIO_free_all(bio);
    string output((char *)buffer, decoded_length);
    free(buffer);

    return output;
}

// Extract `kid` from JWT header
string extract_kid(const string &token)
{
    size_t first_dot = token.find('.');
    if (first_dot == string::npos)
        return "";
    string header_b64 = token.substr(0, first_dot);
    string header_json = base64_url_decode(header_b64);

    json header = json::parse(header_json);
    return header["kid"];
}

// Extract and validate expiration (`exp`)
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

// Function to retrieve public key from JWKS cache
string get_public_key(const string &kid)
{
    string jwks_data = get_cached_jwks();
    if (jwks_data.empty())
    {
        log_message(DEBUG, "JWKS cache is empty.");
        return "";
    }

    json jwks = json::parse(jwks_data);
    for (const auto &key : jwks["keys"])
    {
        if (key["kid"] == kid)
        {
            return "-----BEGIN CERTIFICATE-----\n" + key["x5c"][0].get<string>() + "\n-----END CERTIFICATE-----\n";
        }
    }
    return "";
}

// Convert PEM certificate to RSA Public Key
EVP_PKEY *convert_pem_to_evp(const string &pem_cert)
{
    BIO *bio = BIO_new_mem_buf(pem_cert.c_str(), -1);
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!x509)
    {
        BIO_free(bio);
        throw runtime_error("Failed to parse certificate");
    }

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    X509_free(x509);
    BIO_free(bio);
    return pkey;
}

// Verify JWT Signature
bool verify_signature(EVP_PKEY *public_key, const string &header_payload, const string &signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkey_ctx = NULL;
    bool result = false;

    if (!ctx)
        return false;

    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, public_key) <= 0)
        goto cleanup;
    if (EVP_DigestVerifyUpdate(ctx, header_payload.c_str(), header_payload.size()) <= 0)
        goto cleanup;

    if (EVP_DigestVerifyFinal(ctx, (unsigned char *)signature.data(), signature.size()) == 1)
    {
        result = true;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    return result;
}

// Verify JWT
bool verify_jwt(const string &token)
{
    try
    {
        if (!validate_expiration(token))
            return false;

        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);
        if (first_dot == string::npos || second_dot == string::npos)
            return false;

        string header_payload = token.substr(0, second_dot);
        string signature_b64 = token.substr(second_dot + 1);
        string signature = base64_url_decode(signature_b64);

        string jwks_data = fetch_jwks();
        json jwks = json::parse(jwks_data);

        string kid = extract_kid(token);
        json key;
        for (const auto &k : jwks["keys"])
        {
            if (k["kid"] == kid)
            {
                key = k;
                break;
            }
        }
        if (key.empty())
            return false;

        EVP_PKEY *public_key = convert_pem_to_evp(get_public_key(kid));
        if (!public_key)
            return false;

        bool valid_signature = verify_signature(public_key, header_payload, signature);
        EVP_PKEY_free(public_key);

        return valid_signature;
    }
    catch (...)
    {
        return false;
    }
}

// HTTP request handler
MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method, const char *version,
                           const char *upload_data, size_t *upload_data_size, void **ptr)
{

    const char *auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");

    string response_text;
    int status_code = MHD_HTTP_FORBIDDEN;

    if (auth_header && strncmp(auth_header, "Bearer ", 7) == 0)
    {
        string token(auth_header + 7);

        if (verify_jwt(token))
        {
            response_text = "JWT is valid.";
            status_code = MHD_HTTP_OK;
        }
        else
        {
            response_text = "JWT verification failed.";
        }
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(response_text.size(),
                                                                    (void *)response_text.c_str(),
                                                                    MHD_RESPMEM_MUST_COPY);
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return static_cast<MHD_Result>(ret);
}

// Start HTTP server
void start_server()
{
    log_message(INFO, "HTTP Server running on port " + to_string(PORT));

    http_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, PORT,
                                   NULL, NULL, &request_handler, NULL,
                                   MHD_OPTION_END);
    if (!daemon)
    {
        log_message(ERROR, "Failed to start HTTP server.");
        return;
    }

    // Wait until signal is received
    while (running)
    {
        sleep(1); // Prevents busy-waiting
    }

    log_message(INFO, "Stopping HTTP server...");
    MHD_stop_daemon(http_daemon);
}

// Main function
int main()
{
    set_log_level();

    thread(jwks_updater).detach();

    // Setup signal handlers
    struct sigaction action{};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    start_server();
    return 0;
}
