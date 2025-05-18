cmake_minimum_required(VERSION 3.26)
project(bypass VERSION 1.0.0)

set(COMMON_DIR ${CMAKE_SOURCE_DIR}/common)

file(GLOB COMMON_SOURCES "${COMMON_DIR}/*.cpp")

add_library(bypass SHARED
    dllmain.cpp
    ${COMMON_SOURCES}
)

# Set include directories
target_include_directories(bypass PRIVATE ${COMMON_DIR})

# Consolidate linking
target_link_libraries(bypass PRIVATE ${COMMON_DIR}/detours.lib build_config Ws2_32.lib winmm.lib comsuppw.lib)

# Set output properties
set_target_properties(bypass PROPERTIES OUTPUT_NAME "bypass-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
