cmake_minimum_required(VERSION 3.26)

project(fuzzer)

GETCURRENTFOLDER()
STANDARDSUBPROJECT(${current_folder})
VSUBFOLDER(${current_folder} "Utils")

target_compile_features(fuzzer PRIVATE cxx_std_20)
if(MSVC)
	target_compile_options(fuzzer PRIVATE "/MP")
endif()

include_directories( ${ION_NET_INCLUDE_DIRS} ) 

target_link_libraries(ion-net)




