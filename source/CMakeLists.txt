cmake_minimum_required(VERSION 3.26.3)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(Binance_APP)



include_directories(${CMAKE_SOURCE_DIR}/../include)
link_directories(${CMAKE_SOURCE_DIR}/../lib/cpr)
link_directories(${CMAKE_SOURCE_DIR}/../lib/openssl)

add_executable(Binance main.cpp)

target_link_libraries(Binance cpr libssl)









