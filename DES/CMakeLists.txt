cmake_minimum_required (VERSION 3.15)
project ("DES")

aux_source_directory(./ SRC)
add_executable (DES ${SRC})

set_property(TARGET DES PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")