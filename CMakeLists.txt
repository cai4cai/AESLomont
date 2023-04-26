cmake_minimum_required(VERSION 3.25)
project(AESLomont)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_program(CLANG_TIDY_EXE NAMES clang-tidy PATHS /opt/homebrew/opt/llvm/bin/)
if(NOT CLANG_TIDY_EXE)
  message(STATUS "clang-tidy not found. Skipping corresponding checks.")
else()
  set(CMAKE_CXX_CLANG_TIDY 
    ${CLANG_TIDY_EXE};
    -header-filter=.*fast_marching_method*;
    -checks=-*,portability-*,bugprone-*,-bugprone-easily-swappable-parameters,readability-,clang-analyzer-*,-clang-analyzer-security.insecureAPI.rand,performance-*;
    )
  message(STATUS "Found clang-tidy: ${CLANG_TIDY_EXE}.")
endif()

# Default to release build
if(NOT CMAKE_BUILD_TYPE)
  #set(CMAKE_BUILD_TYPE Release)
  #set(CMAKE_BUILD_TYPE RelWithDebInfo)
  set(CMAKE_BUILD_TYPE Debug)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if(MSVC)
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
  set(CompilerFlags
          CMAKE_CXX_FLAGS
          CMAKE_CXX_FLAGS_DEBUG
          CMAKE_CXX_FLAGS_RELEASE
          CMAKE_C_FLAGS
          CMAKE_C_FLAGS_DEBUG
          CMAKE_C_FLAGS_RELEASE)
  foreach(CompilerFlag ${CompilerFlags})
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
  endforeach()
  message(STATUS "CXX flags (release): ${CMAKE_CXX_FLAGS_RELEASE}")
  message(STATUS "CXX flags (debug): ${CMAKE_CXX_FLAGS_DEBUG}")
endif()

# Warnings Compiler Flags
set(MyWarningFlags
  $<$<CXX_COMPILER_ID:MSVC>:/W4>
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Wno-gnu-zero-variadic-macro-arguments>
)
# message(STATUS "Warning flags: ${MyWarningFlags}")

if(MSVC)
  string( REPLACE "/DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
else()
  string( REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
endif()


# AES executable
add_executable(aes-test
  main.cpp
  AES.cpp)

# Warnings Compiler Flags
target_compile_options(aes-test PRIVATE ${MyWarningFlags})


# Rijndael executable
add_executable(rijndael-test
  main.cpp
  Rijndael.cpp)

# Warnings Compiler Flags
target_compile_options(rijndael-test PRIVATE ${MyWarningFlags})

target_compile_definitions(rijndael-test PRIVATE USE_SLOW_RIJNDAEL)


# Add to ctest
enable_testing()
add_test(NAME aes-test COMMAND aes-test)
add_test(NAME rijndael-test COMMAND rijndael-test)