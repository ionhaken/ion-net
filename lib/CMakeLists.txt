cmake_minimum_required(VERSION 3.9.4)

set( ION_NET_INTERNAL_INCLUDE_DIRS 
	${PROJECT_SOURCE_DIR}/src
	${PROJECT_SOURCE_DIR}/depend/ion/src
	${PROJECT_SOURCE_DIR}/depend/ion/3rdparty
	${PROJECT_SOURCE_DIR}/depend/libsodium/src
	${PROJECT_SOURCE_DIR}/depend
)

add_subdirectory(lib-static)

FILE(GLOB ALL_HEADER_SRCS ${PROJECT_SOURCE_DIR}/src/*.h)
INSTALL(FILES ${ALL_HEADER_SRCS} DESTINATION ${CMAKE_PREFIX_PATH}/include/ion)