cmake_minimum_required(VERSION 3.26)

FILE(GLOB_RECURSE ALL_HEADER_SRCS ${PROJECT_SOURCE_DIR}/src/*.h)
FILE(GLOB_RECURSE ALL_CPP_SRCS ${PROJECT_SOURCE_DIR}/src/*.cpp)

project(ion-net-dll)

include_directories( ${ION_NET_INTERNAL_INCLUDE_DIRS} ) 

add_library(ion-net-dll SHARED ${ALL_CPP_SRCS} ${ALL_HEADER_SRCS})
	
IF(WIN32 AND NOT UNIX)
	SET( CMAKE_CXX_FLAGS "/D WIN32 /D _ION_NET_DLL /D _CRT_NONSTDC_NO_DEPRECATE /D _CRT_SECURE_NO_DEPRECATE /GS- /GR- ")
ENDIF(WIN32 AND NOT UNIX)

IF(WIN32 AND NOT UNIX)
	target_link_libraries (ion-net-dll ${ION_NET_LIBRARY_LIBS})
ELSE(WIN32 AND NOT UNIX)
	target_link_libraries (ion-net-dll ${ION_NET_LIBRARY_LIBS})
	INSTALL(TARGETS ion-net-dll DESTINATION ${PROJECT_SOURCE_DIR}/lib/dll)
ENDIF(WIN32 AND NOT UNIX)
target_compile_features(ion-net-dll PRIVATE cxx_std_20)
if(MSVC)
	target_compile_options(ion-net-dll PRIVATE "/MP")
endif()

install(TARGETS ion-net-dll 
        RUNTIME DESTINATION ${CMAKE_PREFIX_PATH}/bin
        ARCHIVE DESTINATION ${CMAKE_PREFIX_PATH}/lib
    )