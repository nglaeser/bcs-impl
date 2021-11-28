cmake_minimum_required (VERSION 3.9)
project (bcs-impl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

find_library(EMP-TOOL_LIBRARY NAMES emp-tool)

include_directories(/usr/local/include/)
include_directories(include/)

add_executable (main src/main.cpp)
target_link_libraries(main ${EMP-TOOL_LIBRARY})