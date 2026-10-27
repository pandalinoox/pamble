cmake_minimum_required(VERSION 3.31)

project(pamble
    VERSION 0.1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
)

add_executable(pamble
    src/main.c
    src/pamble_sha256.c
    src/pamble_hmac_sha256.c
    src/pamble_pbkdf2.c
    src/pamble_archive.c
)

target_include_directories(pamble
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_compile_definitions(pamble
    PRIVATE
        _POSIX_C_SOURCE=200809L
)

enable_testing()

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRITERION REQUIRED criterion)

add_executable(pamble_tests
    tests/test_pamble_sha256.c
    tests/test_pamble_hmac_sha256.c
    tests/test_pamble_pdkdf2.c
    tests/test_pamble_archive.c
    src/pamble_sha256.c
    src/pamble_hmac_sha256.c
    src/pamble_pbkdf2.c
    src/pamble_archive.c
)

target_include_directories(pamble_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${CRITERION_INCLUDE_DIRS}
)

target_compile_definitions(pamble_tests
    PRIVATE
        _POSIX_C_SOURCE=200809L
        _XOPEN_SOURCE=700
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
