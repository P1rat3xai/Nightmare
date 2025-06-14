cmake_minimum_required(VERSION 3.10)
project(ClangTool)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_executable(clang_tool tool.cpp)
target_link_libraries(clang_tool
  PRIVATE
  clangTooling
  clangBasic
  clangASTMatchers
)
