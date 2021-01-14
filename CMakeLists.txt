project(openssl_test)

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB openssl_test_SRC_SRV server/*.H server/*.cpp)
file(GLOB openssl_test_SRC_CLIENT client/*.H client/*.cpp)

SET(CMAKE_EXE_LINKER_FLAGS "-ljsoncpp -lssl -lcrypto -lpthread")

#debug
#add_compile_options(-g3)

add_executable(server ${openssl_test_SRC_SRV})
add_executable(client ${openssl_test_SRC_CLIENT})
