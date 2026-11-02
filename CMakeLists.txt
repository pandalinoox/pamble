cmake_minimum_required(VERSION 3.31)

project(pamble
    VERSION 1.0.0
    LANGUAGES C
)

option(PAMBLE_BUILD_TESTS "Build the Criterion test suite" ON)
option(PAMBLE_STATIC "Link the pamble binary statically (release builds)" OFF)

include(GNUInstallDirs)

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

set(PAMBLE_LIBRARY_SOURCES
    src/pamble_sha256.c
    src/pamble_hmac_sha256.c
    src/pamble_pbkdf2.c
    src/pamble_archive.c
    src/pamble_aes.c
    src/pamble_aes_ctr.c
    src/pamble_progress.c
    src/pamble_crypto.c
)

add_executable(pamble
    src/main.c
    ${PAMBLE_LIBRARY_SOURCES}
)

target_include_directories(pamble
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_compile_definitions(pamble
    PRIVATE
        _POSIX_C_SOURCE=200809L
        _GNU_SOURCE
        PAMBLE_VERSION="${PROJECT_VERSION}"
)

if(PAMBLE_STATIC)
    target_link_options(pamble PRIVATE -static)
endif()

install(TARGETS pamble RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(PAMBLE_BUILD_TESTS)
    enable_testing()

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CRITERION REQUIRED criterion)

    add_executable(pamble_tests
        tests/test_pamble_sha256.c
        tests/test_pamble_hmac_sha256.c
        tests/test_pamble_pdkdf2.c
        tests/test_pamble_archive.c
        tests/test_pamble_aes.c
        tests/test_pamble_aes_ctr.c
        tests/test_pamble_progress.c
        tests/test_pamble_crypto.c
        ${PAMBLE_LIBRARY_SOURCES}
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
            _GNU_SOURCE
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
endif()
