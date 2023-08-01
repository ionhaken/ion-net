cmake_minimum_required(VERSION 3.26)

project(ion-net)

set( ION_NET_HEADERFILES ${PROJECT_SOURCE_DIR}/src) #This name doesn't follow CMake conventions but for retro compatibility I'll let it there.

set(ION_NET_COMMON_LIBS ion-net)

MACRO(GETCURRENTFOLDER)#Gets the current foldername without the path
	string(REGEX REPLACE
	  ".+/(.?)"
	  "\\1"
	  current_folder "${CMAKE_CURRENT_SOURCE_DIR}")
ENDMACRO(GETCURRENTFOLDER)

MACRO(STANDARDSUBPROJECT PROJECTNAME)#Many of the projects just need the cpp files compiled and the header added to the project, this avoids repeating code
	project(${PROJECTNAME})
	FILE(GLOB_RECURSE ALL_CPP_SRCS *.cpp)
	FILE(GLOB_RECURSE ALL_HEADER_SRCS *.h)
	include_directories(${ION_NET_HEADERFILES} ./) 
	add_executable(${PROJECTNAME} ${ALL_CPP_SRCS} ${ALL_HEADER_SRCS} ${READMES})
	target_link_libraries(${PROJECTNAME} ${ION_NET_COMMON_LIBS})
ENDMACRO(STANDARDSUBPROJECT)

MACRO(VSUBFOLDER PROJECTNAME FOLDERNAME)#A macro interface for adding solution folders with a patched cmake
	set_target_properties(${PROJECTNAME} PROPERTIES FOLDER ${FOLDERNAME})
ENDMACRO(VSUBFOLDER)

set(PREDEFINED_TARGETS_FOLDER "CustomTargets")

# Network update interval.
add_definitions(-DION_NET_WORK_INTERVAL=10)

add_definitions(-DHASEXCEPTIONS=0)

# Disable Strict API for release
add_compile_options(
	"$<$<CONFIG:RELEASE>:-DION_API_STRICT=0>"
	"$<$<CONFIG:RELWITHDEBINFO>:-DION_API_STRICT=0>"
	"$<$<CONFIG:MINSIZEREL>:-DION_API_STRICT=0>"
)

# Disable dev tools for release
add_compile_options(
	"$<$<CONFIG:RELEASE>:-DION_CONFIG_DEV_TOOLS=0>"
	"$<$<CONFIG:RELWITHDEBINFO>:-DION_CONFIG_DEV_TOOLS=0>"
	"$<$<CONFIG:MINSIZEREL>:-DION_CONFIG_DEV_TOOLS=0>"
)

add_compile_options(
	"$<$<CONFIG:RELEASE>:-DION_CONFIG_ERROR_CHECKING=0>"
    "$<$<CONFIG:DEBUG>:-DION_DEBUG_LOG_ENABLED=0>"
)


IF (WIN32 AND NOT UNIX)
	set (PROGRAMFILESX86 $ENV{PROGRAMFILES})
	string(REPLACE "\\" "/" PROGRAMFILESX86 ${PROGRAMFILESX86})
ENDIF(WIN32 AND NOT UNIX)

IF (WIN32 AND NOT UNIX)
	set(ION_NET_LIBRARY_LIBS ws2_32.lib ion-core libsodium tlsf Dbghelp)
ELSE(WIN32 AND NOT UNIX)
	set(ION_NET_LIBRARY_LIBS pthread ion-core libsodium tlsf)
ENDIF(WIN32 AND NOT UNIX)

set(CMAKE_DEBUG_POSTFIX "_d")

# Options
option( ION_NET_GENERATE_INCLUDE_ONLY_DIR "Setup a include/ion-net/ directory in which all the headers are copied." FALSE )

if( ION_NET_GENERATE_INCLUDE_ONLY_DIR )
	set( ION_NET_INCLUDE_ONLY_DIR ${PROJECT_SOURCE_DIR}/include ) # this will be visible by client code
	set( ION_NET_NAMED_INCLUDE_ONLY_DIR ${ION_NET_INCLUDE_ONLY_DIR}/ion-net )
	message( STATUS "Setting up the ${ION_NET_NAMED_INCLUDE_ONLY_DIR} directory..." )
	# Now setup the include/ion-net/*.h files.
	file( MAKE_DIRECTORY ${ION_NET_NAMED_INCLUDE_ONLY_DIR} )
	file( COPY ${ION_NET_HEADERFILES}/ DESTINATION ${ION_NET_NAMED_INCLUDE_ONLY_DIR} FILES_MATCHING PATTERN "*.h"  )
	message( STATUS "DONE: Setting up the ${ION_NET_NAMED_INCLUDE_ONLY_DIR} directory." )
endif()

set( ION_NET_INCLUDE_DIRS 
	${ION_NET_HEADERFILES} 
	${ION_NET_INCLUDE_ONLY_DIR} 
	${PROJECT_SOURCE_DIR}/src/ion
	${PROJECT_SOURCE_DIR}/depend/libsodium/src
	${PROJECT_SOURCE_DIR}/depend/ion-core/src
	${PROJECT_SOURCE_DIR}/depend/ion-core/depend)

FILE(GLOB_RECURSE ALL_HEADER_SRCS ${PROJECT_SOURCE_DIR}/src/*.h)
FILE(GLOB_RECURSE ALL_CPP_SRCS ${PROJECT_SOURCE_DIR}/src/*.cpp)
FILE(GLOB_RECURSE ALL_C_SRCS ${PROJECT_SOURCE_DIR}/src/*.c)


add_library(ion-net STATIC ${ALL_CPP_SRCS} ${ALL_HEADER_SRCS} ${ALL_C_SRCS})

source_group(TREE ${PROJECT_SOURCE_DIR}/src/ion FILES ${ALL_CPP_SRCS} ${ALL_HEADER_SRCS} ${ALL_C_SRCS})

include_directories( ${ION_NET_INCLUDE_DIRS} ) 


IF(WIN32 AND NOT UNIX)
	SET( CMAKE_CXX_FLAGS "/D WIN32 /D _RAKNET_LIB /D _CRT_NONSTDC_NO_DEPRECATE /D _CRT_SECURE_NO_DEPRECATE /GS- /GR- /EHsc")
ENDIF(WIN32 AND NOT UNIX)

IF(WIN32 AND NOT UNIX)
	target_link_libraries (ion-net ${ION_NET_LIBRARY_LIBS})

	IF(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")

		IF( MSVC10 OR MSVC11 OR MSVC12 OR MSVC14 )
			set_target_properties(ion-net PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:\"LIBCD.lib LIBCMTD.lib MSVCRT.lib\"" )
		ELSE()
			set_target_properties(ion-net PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:&quot;LIBCD.lib LIBCMTD.lib MSVCRT.lib&quot;" )
		ENDIF()
				
	ENDIF(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")

ELSE(WIN32 AND NOT UNIX)
	target_link_libraries (ion-net ${ION_NET_LIBRARY_LIBS})
	INSTALL(TARGETS ion-net DESTINATION ${PROJECT_SOURCE_DIR}/lib/lib-static)
ENDIF(WIN32 AND NOT UNIX)

target_compile_features(ion-net PRIVATE cxx_std_20)
if(MSVC)
	target_compile_options(ion-net PRIVATE "/MP")
endif()

install(TARGETS ion-net 
        ARCHIVE DESTINATION ${CMAKE_PREFIX_PATH}/lib
    )

set_target_properties(ion-net PROPERTIES FOLDER "Lib")


add_subdirectory(samples)
add_subdirectory(depend)

