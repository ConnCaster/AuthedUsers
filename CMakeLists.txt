cmake_minimum_required(VERSION 3.16)

project(authed_users_info_standalone LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SystemD REQUIRED IMPORTED_TARGET libsystemd)

add_executable(authed_users_info
        main.cpp
)

target_link_libraries(authed_users_info PRIVATE
        PkgConfig::SystemD
)