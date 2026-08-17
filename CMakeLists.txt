cmake_minimum_required(VERSION 3.31)

project(pamble
    VERSION 0.1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
)

add_executable(pamble
    src/main.c
    src/sha256.c
)

target_include_directories(pamble
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

enable_testing()

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRITERION REQUIRED criterion)

add_executable(pamble_tests
    tests/test_sha256.c
    src/sha256.c
)

target_include_directories(pamble_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${CRITERION_INCLUDE_DIRS}
)

target_link_directories(pamble_tests
    PRIVATE
        ${CRITERION_LIBRARY_DIRS}
)

target_link_libraries(pamble_tests
    PRIVATE
        ${CRITERION_LIBRARIES}
)

add_test(
    NAME pamble_tests
    COMMAND pamble_tests
)
