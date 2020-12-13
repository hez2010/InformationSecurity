cmake_minimum_required (VERSION 3.15)
project ("Kerberos")

set(CMAKE_CXX_STANDARD "17")
set(CMAKE_C_STANDARD "11")

add_library(DES STATIC "DES.c")
add_library(Utils STATIC "Utils.c")
add_executable(AuthServer "AuthServer.c")
add_executable(TGServer "TGServer.c")
add_executable(SvcServer "SvcServer.c")
add_executable(Client "Client.c")

target_link_libraries(AuthServer DES Utils)
target_link_libraries(TGServer DES Utils)
target_link_libraries(SvcServer DES Utils)
target_link_libraries(Client DES Utils)

set_property(TARGET DES PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET Utils PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET AuthServer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET TGServer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET SvcServer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET Client PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
