cmake_minimum_required(VERSION 3.10)
project(SCAD-Exercise01)

find_package(Threads REQUIRED)


# set default build type to release if nothing else is specified
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    # overwrite empty build type
    set(CMAKE_BUILD_TYPE "${default_build_type}")
endif()


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -Wextra -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter -Wno-unused-variable")

set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DDEBUGMODE=0")

set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DDEBUGMODE=1 -ggdb")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUGMODE=1")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG") # enable debug features in libcstd++
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize-recover=address")

add_library(tinycrypt SHARED
  ./tinycrypt/tinycrypt.cc
  ./tinycrypt/tiny-AES-c/aes.c
  ./tinycrypt/hmac_sha256/hmac_sha256.c
  ./tinycrypt/hmac_sha256/sha256.c
)

set_target_properties(tinycrypt PROPERTIES
  VERSION 1.0.0
  SOVERSION 1
  OUTPUT_NAME tinycrypt
)

add_executable(server
  server.cc
  base64.cc
  ./simple_networking.h)

add_executable(client
  client.cc
  base64.cc
  ./simple_networking.h)

target_link_libraries(server PRIVATE tinycrypt Threads::Threads)

target_link_libraries(client PRIVATE tinycrypt)
