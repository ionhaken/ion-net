cmake_minimum_required(VERSION 3.26)

FILE(GLOB_RECURSE ALL_HEADER_SRCS ${PROJECT_SOURCE_DIR}/src/*.h)
FILE(GLOB_RECURSE ALL_CPP_SRCS ${PROJECT_SOURCE_DIR}/src/*.cpp)

project(ion-net-lib-static)

include_directories( ${ION_NET_INTERNAL_INCLUDE_DIRS} ) 

add_library(ion-net-lib-static STATIC ${ALL_CPP_SRCS} ${ALL_HEADER_SRCS})

IF(WIN32 AND NOT UNIX)
	SET( CMAKE_CXX_FLAGS "/D WIN32 /D _RAKNET_LIB /D _CRT_NONSTDC_NO_DEPRECATE /D _CRT_SECURE_NO_DEPRECATE /GS- /GR- /EHsc")
ENDIF(WIN32 AND NOT UNIX)

IF(WIN32 AND NOT UNIX)
	target_link_libraries (ion-net-lib-static ${ION_NET_LIBRARY_LIBS})

	IF(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")

		IF( MSVC10 OR MSVC11 OR MSVC12 OR MSVC14 )
			set_target_properties(ion-net-lib-static PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:\"LIBCD.lib LIBCMTD.lib MSVCRT.lib\"" )
		ELSE()
			set_target_properties(ion-net-lib-static PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:&quot;LIBCD.lib LIBCMTD.lib MSVCRT.lib&quot;" )
		ENDIF()
				
	ENDIF(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")

ELSE(WIN32 AND NOT UNIX)
	target_link_libraries (ion-net-lib-static ${ION_NET_LIBRARY_LIBS})
	INSTALL(TARGETS ion-net-lib-static DESTINATION ${PROJECT_SOURCE_DIR}/lib/lib-static)
ENDIF(WIN32 AND NOT UNIX)

target_compile_features(ion-net-lib-static PRIVATE cxx_std_20)
if(MSVC)
	target_compile_options(ion-net-lib-static PRIVATE "/MP")
endif()
	
install(TARGETS ion-net-lib-static 
        ARCHIVE DESTINATION ${CMAKE_PREFIX_PATH}/lib
    )
