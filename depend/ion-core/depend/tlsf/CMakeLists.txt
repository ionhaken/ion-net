cmake_minimum_required(VERSION 3.9.4)

project(tlsf LANGUAGES C)

add_library(tlsf STATIC tlsf.c)

include_directories(../../src)

install(FILES tlsf.h 
	TYPE INCLUDE
)

install(TARGETS tlsf
    EXPORT tlsf-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT tlsf-targets
    FILE tlsf-config.cmake
    NAMESPACE tlsf::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tlsf
)

set_target_properties(tlsf PROPERTIES FOLDER "Lib")