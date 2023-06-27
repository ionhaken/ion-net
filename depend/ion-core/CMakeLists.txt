cmake_minimum_required(VERSION 3.9.4)

project(ion-core)

add_subdirectory("depend")

file(GLOB_RECURSE SRCS src/ion/*.cpp)
file(GLOB_RECURSE HDRS src/ion/*.h)
file(GLOB_RECURSE INLS src/ion/*.inl)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/src/ion FILES ${SRCS} ${HDRS} ${INLS})

include_directories(src)
include_directories(depend)

add_definitions(-DUNICODE -D_UNICODE)
add_library(ion-core STATIC  ${SRCS} ${HDRS} ${INLS})

target_compile_features(ion-core PRIVATE cxx_std_20)

set_target_properties(ion-core PROPERTIES FOLDER "Lib")



