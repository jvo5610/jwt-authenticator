cmake_minimum_required(VERSION 3.14)
project(auth-server)

# Required
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)

# Curl
find_library(CURL_LIB curl)
find_path(CURL_INCLUDE_DIR curl/curl.h PATH_SUFFIXES curl)
if (NOT CURL_LIB)
    message(FATAL_ERROR "libcurl not found!")
endif()

# libhv
find_path(HV_INCLUDE_DIR hv/WebSocketServer.h)
find_library(HV_LIB hv)
if (NOT HV_INCLUDE_DIR OR NOT HV_LIB)
    message(FATAL_ERROR "libhv not found")
endif()

message(STATUS "Found CURL: ${CURL_LIB}, ${CURL_INCLUDE_DIR}")
message(STATUS "Found libhv: ${HV_LIB}, ${HV_INCLUDE_DIR}")

include_directories(
    ${CURL_INCLUDE_DIR}
    ${HV_INCLUDE_DIR}
)

add_executable(auth-server src/main.cpp)

# Links
target_link_libraries(auth-server
    PRIVATE
    ${CURL_LIB}
    ${HV_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)
