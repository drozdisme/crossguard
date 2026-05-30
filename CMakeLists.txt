cmake_minimum_required(VERSION 3.16)
project(crossguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

include_directories(${PROJECT_SOURCE_DIR}/include)

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
add_library(crossguard_lib ${LIB_SOURCES})

add_executable(crossguard-cli src/main.cpp)
target_link_libraries(crossguard-cli PRIVATE crossguard_lib)

enable_testing()
add_executable(crossguard-tests tests/test_crossguard.cpp)
target_link_libraries(crossguard-tests PRIVATE crossguard_lib)
add_test(NAME all COMMAND crossguard-tests)

install(TARGETS crossguard-cli DESTINATION bin)
install(DIRECTORY fixtures/ DESTINATION share/crossguard/fixtures)
