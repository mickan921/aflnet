cmake_minimum_required(VERSION 3.16)

project(WinAFLNet C)

if(MSVC)
  message(FATAL_ERROR "The current WinAFLNet/AFLNet C sources use GNU C extensions. Use MinGW GCC or clang on Windows.")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_library(aflnet_core OBJECT aflnet.c)
target_compile_definitions(aflnet_core PRIVATE MESSAGES_TO_STDOUT)

foreach(tool IN ITEMS afl-replay aflnet-replay)
  add_executable(${tool} ${tool}.c $<TARGET_OBJECTS:aflnet_core>)
  target_compile_definitions(${tool} PRIVATE MESSAGES_TO_STDOUT)
  if(WIN32)
    target_link_libraries(${tool} PRIVATE ws2_32)
  endif()
endforeach()

if(WIN32)
  add_library(aflnet-win-sancov STATIC examples/windows/aflnet_win_sancov.c)

  add_executable(aflnet-win-fuzz aflnet-win-fuzz.c $<TARGET_OBJECTS:aflnet_core>)
  target_compile_definitions(aflnet-win-fuzz PRIVATE MESSAGES_TO_STDOUT)
  target_link_libraries(aflnet-win-fuzz PRIVATE ws2_32 dbghelp)

  add_executable(aflnet-win-rtsp-smoke examples/windows/rtsp_smoke_server.c)
  target_link_libraries(aflnet-win-rtsp-smoke PRIVATE ws2_32)
endif()
