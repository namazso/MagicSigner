cmake_minimum_required(VERSION 3.25)

project(MagicSigner)

add_library(${PROJECT_NAME} SHARED library.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE crypt32)

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "XmlLite")

target_link_options(${PROJECT_NAME} PRIVATE
        /ENTRY:DllEntry
        /NOCOFFGRPINFO
        /Brepro
        /PDBALTPATH:%_PDB%
        )
