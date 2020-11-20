cmake_minimum_required (VERSION 3.15)
project ("HMACMD5")

aux_source_directory(./ SRC)
add_executable (HMACMD5 ${SRC})

set_property(TARGET HMACMD5 PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
