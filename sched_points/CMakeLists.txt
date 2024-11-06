cmake_minimum_required(VERSION 3.13)
project(InjectSchedPoint)

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(InjectSchedPoint SHARED ./InjectSchedPoint.pass.cc)

llvm_map_components_to_libnames(llvm_libs core support)

target_link_libraries(InjectSchedPoint PRIVATE ${LLVM_LIBS})

set_target_properties(InjectSchedPoint PROPERTIES
    COMPILE_FLAGS "-fno-rtti"
)