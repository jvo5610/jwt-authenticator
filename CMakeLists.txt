cmake_minimum_required(VERSION 3.14)
project(auth-server)

find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(CURL_LIB curl)
find_path(CURL_INCLUDE_DIR curl/curl.h PATH_SUFFIXES curl)

find_library(MICROHTTPD_LIB microhttpd)
find_path(MICROHTTPD_INCLUDE_DIR microhttpd.h PATH_SUFFIXES microhttpd)

if (NOT CURL_LIB)
    message(FATAL_ERROR "libcurl not found!")
endif()

if (NOT MICROHTTPD_LIB)
    message(FATAL_ERROR "libmicrohttpd not found!")
endif()

message(STATUS "Found CURL: ${CURL_LIB}, ${CURL_INCLUDE_DIR}")
message(STATUS "Found Microhttpd: ${MICROHTTPD_LIB}, ${MICROHTTPD_INCLUDE_DIR}")

include_directories(${CURL_INCLUDE_DIR} ${MICROHTTPD_INCLUDE_DIR})

add_executable(auth-server src/main.cpp)

target_link_libraries(auth-server PRIVATE ${CURL_LIB} ${MICROHTTPD_LIB} OpenSSL::SSL OpenSSL::Crypto)
