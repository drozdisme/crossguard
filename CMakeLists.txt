cmake_minimum_required(VERSION 3.16)
project(crossguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)

# Library (all src/ except main.cpp)
file(GLOB LIB_SOURCES
    "src/cairo_parser.cpp"
    "src/correlator.cpp"
    "src/detectors.cpp"
    "src/engine.cpp"
    "src/formatters.cpp"
    "src/json.cpp"
    "src/solidity_parser.cpp"
    "src/taint_engine.cpp"
)
add_library(crossguard ${LIB_SOURCES})
target_link_libraries(crossguard PUBLIC OpenSSL::Crypto)

# CLI
add_executable(crossguard-cli src/main.cpp)
target_link_libraries(crossguard-cli PRIVATE crossguard)

# Tests
enable_testing()
add_executable(crossguard-tests tests/test_crossguard.cpp)
target_link_libraries(crossguard-tests PRIVATE crossguard)
add_test(NAME crossguard COMMAND crossguard-tests)

# Installation
install(TARGETS crossguard-cli DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY fixtures/ DESTINATION share/crossguard/fixtures)
