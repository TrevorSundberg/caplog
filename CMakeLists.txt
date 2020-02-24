cmake_minimum_required(VERSION 3.2)
project(muxd)
add_executable(muxd
    src/main.cpp
    src/muxd.cpp
)
set_property(TARGET muxd PROPERTY CXX_STANDARD 20)

find_package(Threads REQUIRED)

find_package(cxxopts CONFIG REQUIRED)

find_package(date CONFIG REQUIRED)

target_link_libraries(muxd PRIVATE
  "${CMAKE_THREAD_LIBS_INIT}"
  cxxopts::cxxopts
  date::date
  date::tz
)