cmake_minimum_required(VERSION 3.26)
GETCURRENTFOLDER()
STANDARDSUBPROJECT(${current_folder})
VSUBFOLDER(${current_folder} "Internal Tests")

target_compile_features(benchmark PRIVATE cxx_std_20)
if(MSVC)
	target_compile_options(benchmark PRIVATE "/MP")
endif()

include_directories( ${ION_NET_INCLUDE_DIRS} ) 




