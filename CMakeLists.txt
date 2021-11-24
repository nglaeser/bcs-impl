cmake_minimum_required (VERSION 3.9)
project (bcs-impl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(/usr/local/include)
include_directories(includes)

add_executable (main src/main.cpp)