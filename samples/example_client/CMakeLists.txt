cmake_minimum_required(VERSION 3.26)

project(example_client)

include_directories( 
	${ION_NET_INCLUDE_DIRS} 
	) 

GETCURRENTFOLDER()
STANDARDSUBPROJECT(${current_folder})
VSUBFOLDER(${current_folder} "Samples")

target_compile_features(example_client PRIVATE cxx_std_20)
if(MSVC)
	target_compile_options(example_client PRIVATE "/MP")
endif()





