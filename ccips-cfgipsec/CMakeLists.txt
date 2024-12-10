cmake_minimum_required(VERSION 3.10)
set(CMAKE_BUILD_TYPE Debug)
message(STATUS "Selected target is ${TARGET}")


set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -Wall -Wextra -pthread")

# set the project name and version
set (PROJECT_NAME "i2nsf_cfgipsec")
project(${PROJECT_NAME} VERSION 1.0)

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build-scripts/CMakeModules/")


set(SRC_DIRECTORY "${PROJECT_SOURCE_DIR}/src")
# Include directories
include_directories("${SRC_DIRECTORY}")

message(STATUS "Add libraries for untrusted")
add_library(i2nsf
"${SRC_DIRECTORY}/sad_entry.c"
"${SRC_DIRECTORY}/spd_entry.c"
"${SRC_DIRECTORY}/utils.c" 
"${SRC_DIRECTORY}/messages.c"
"${SRC_DIRECTORY}/pfkeyv2_utils.c"
"${SRC_DIRECTORY}/pfkeyv2_entry.c"
"${SRC_DIRECTORY}/sysrepo_utils.c"
"${SRC_DIRECTORY}/sysrepo_entries.c"
"${SRC_DIRECTORY}/sysrepo_print.c"
"${SRC_DIRECTORY}/log.c"
"${SRC_DIRECTORY}/sad_entry.h"
"${SRC_DIRECTORY}/spd_entry.h"
"${SRC_DIRECTORY}/utils.h" 
"${SRC_DIRECTORY}/messages.h"
"${SRC_DIRECTORY}/pfkeyv2_utils.h"
"${SRC_DIRECTORY}/pfkeyv2_entry.h"
"${SRC_DIRECTORY}/sysrepo_utils.h"
"${SRC_DIRECTORY}/sysrepo_entries.h"
"${SRC_DIRECTORY}/sysrepo_print.h"
"${SRC_DIRECTORY}/log.h"
)

# Add parson
add_library(parson STATIC "${PROJECT_SOURCE_DIR}/parson/parson.c")
# set_target_properties(parson PROPERTIES PRIVATE_HEADER "parson.h")
include_directories("${PROJECT_SOURCE_DIR}/parson")


# add the executable
add_executable(${PROJECT_NAME} 
    "${PROJECT_SOURCE_DIR}/cmd/i2nsf_ra/main.c"
    # "${PROJECT_SOURCE_DIR}/test_trusted.c"
    "${SRC_DIRECTORY}/constants.h"
    "${SRC_DIRECTORY}/host.h"
)


# Inlude sysrepo
include("${CMAKE_SOURCE_DIR}/build-scripts/ImportSysrepo.cmake")
# Link libraries
message(STATUS "Linking libraries for untrusted target")
target_link_libraries(${PROJECT_NAME} PUBLIC 
    i2nsf
    parson
    ${SYSREPO_LIBRARIES}
    ${LIBYANG_LIBRARIES}
    pthread
)


# add the binary tree to the search path for include files
target_include_directories(${PROJECT_NAME} PUBLIC
    "${PROJECT_BINARY_DIR}"
)


set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "i2nsf_cfgipsec2")


# TODO Add for the untrusted case
# We need to install yang modules
# We need to enable sudo "sysrepoctl -e ikeless-notification -a -c  ietf-i2nsf-ikeless -v3"



