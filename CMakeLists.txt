cmake_minimum_required(VERSION 3.26)

project(ion-net)

set( ION_NET_HEADERFILES ${PROJECT_SOURCE_DIR}/src) #This name doesn't follow CMake conventions but for retro compatibility I'll let it there.

set(ION_NET_COMMON_LIBS ion-net-lib-static)

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


if( NOT APPLE )
# check 64 bit
if( CMAKE_SIZEOF_VOID_P MATCHES "4" )
  set( HAVE_64_BIT 0 )
else(  CMAKE_SIZEOF_VOID_P MATCHES "4")
  set( HAVE_64_BIT 1 )
endif(  CMAKE_SIZEOF_VOID_P MATCHES "4")
endif( NOT APPLE )

IF (WIN32 AND NOT UNIX)
	set (PROGRAMFILESX86 $ENV{PROGRAMFILES})
	string(REPLACE "\\" "/" PROGRAMFILESX86 ${PROGRAMFILESX86})
ENDIF(WIN32 AND NOT UNIX)

IF (WIN32 AND NOT UNIX)
	set(ION_NET_LIBRARY_LIBS ws2_32.lib ion libsodium tlsf Dbghelp)
ELSE(WIN32 AND NOT UNIX)
	set(ION_NET_LIBRARY_LIBS pthread ion libsodium tlsf)
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
	${PROJECT_SOURCE_DIR}/depend/ion/src
	${PROJECT_SOURCE_DIR}/depend/ion/3rdparty)

add_subdirectory(lib)

add_subdirectory(benchmark)
add_subdirectory(fuzzer)
add_subdirectory(depend)