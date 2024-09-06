cmake_minimum_required(VERSION 3.10)

set(TARGET ${TARGET} "untrusted")

message(STATUS, "Selected target is ${TARGET}")

if (${TARGET} STREQUAL "enarx")
    set(CMAKE_C_COMPILER "/home/debian/wasi-sdk-14.0/bin/clang")
    set(CMAKE_CXX_COMPILER "/home/debian/wasi-sdk-14.0/bin/clang")
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra")
# -Wall -Wextra)
endif()



# set the project name and version
set (PROJECT_NAME "I2NSF")
project(${PROJECT_NAME} VERSION 1.0)




include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")




if (${TARGET} STREQUAL "keystone")
    if(RISCV32)
    set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup rv32")
    else()
    set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup")
    endif()
endif()







# Add files to the directory
set(SRC_DIRECTORY "${PROJECT_SOURCE_DIR}/src")
add_library(log "${SRC_DIRECTORY}/log/log.c")
add_library(sad_entry "${SRC_DIRECTORY}/sad_entry/sad_entry.c")
add_library(spd_entry "${SRC_DIRECTORY}/spd_entry/spd_entry.c")
add_library(utils "${SRC_DIRECTORY}/utils/utils.c")
add_library(parson "${PROJECT_SOURCE_DIR}/parson/parson.c")


# Only include this library for non trusted parts
if (${TARGET} STREQUAL "untrusted")
    message(STATUS "Add libraries for untrusted")
    add_library(pfkeyv2_utils 
    "${SRC_DIRECTORY}/pfkeyv2_utils/pfkeyv2_utils.c"
    "${SRC_DIRECTORY}/pfkeyv2_utils/pfkeyv2_entry.c"
    )
    add_library(sysrepo_utils 
    "${SRC_DIRECTORY}/sysrepo_utils/sysrepo_utils.c"
    "${SRC_DIRECTORY}/sysrepo_utils/sysrepo_entries.c"
    "${SRC_DIRECTORY}/sysrepo_utils/sysrepo_print.c")
endif()

# Include directories
include_directories("${SRC_DIRECTORY}")
include_directories("${SRC_DIRECTORY}")
include_directories("${SRC_DIRECTORY}/log")
include_directories("${SRC_DIRECTORY}/utils")
include_directories("${SRC_DIRECTORY}/sad_entry")
include_directories("${SRC_DIRECTORY}/spd_entry")


link_directories("${SRC_DIRECTORY}")
link_directories("${SRC_DIRECTORY}")
link_directories("${SRC_DIRECTORY}/log")
link_directories("${SRC_DIRECTORY}/utils")
link_directories("${SRC_DIRECTORY}/sad_entry")
link_directories("${SRC_DIRECTORY}/spd_entry")

# Only include this library for non trusted parts
if (${TARGET} STREQUAL "untrusted")
    message(STATUS "Including directorories for untrusted target")
    include_directories("${SRC_DIRECTORY}/pfkeyv2_utils")
    link_directories("${SRC_DIRECTORY}/pfkeyv2_utils")
    include_directories("${SRC_DIRECTORY}/sysrepo_utils")
    link_directories("${SRC_DIRECTORY}/sysrepo_utils")
endif()

# add the executable
if (${TARGET} STREQUAL "untrusted")
    add_executable(${PROJECT_NAME} 
    "${PROJECT_SOURCE_DIR}/test_not_trusted.c"
    "${SRC_DIRECTORY}/constants.h"
    "${SRC_DIRECTORY}/host.h"
    )
else()
    add_executable(${PROJECT_NAME} 
        "${PROJECT_SOURCE_DIR}/test_trusted.c"
        "${SRC_DIRECTORY}/constants.h"
    )
endif()

#link sysrepo if needed
if (${TARGET} STREQUAL "untrusted") 

    find_package(Threads REQUIRED)  
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    set(CMAKE_THREAD_LIBS_INIT "-lpthread")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -q")
    set(CMAKE_THREAD_PREFER_PTHREAD ON) 
    target_link_libraries(${PROJECT_NAME} PUBLIC pthread)
    

    message(STATUS "Looking for libyang")
    find_package(LibYANG REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBYANG_LIBRARIES})
    include_directories(${LIBYANG_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBYANG_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBYANG_LIBRARIES})


    message(STATUS "Looking for Sysrepo")
    find_package(Sysrepo REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${SYSREPO_LIBRARIES})
    include_directories(${SYSREPO_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_INCLUDES ${SYSREPO_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${SYSREPO_LIBRARIES})
endif()


 # Only include this for the unstrusted binary
if (${TARGET} STREQUAL "untrusted")   
    message(STATUS "Linking librararies for untrusted target")
    target_link_libraries(${PROJECT_NAME} PUBLIC 
        sysrepo_utils
        pfkeyv2_utils
        log
        sad_entry
        spd_entry
        utils
        parson
    )
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC 
        log
        sad_entry
        spd_entry
        utils
        parson
    )
endif()

# Add Base to I2NSF target_include_directories()
target_include_directories(${PROJECT_NAME} PUBLIC log "${PROJECT_BINARY_DIR}" "${SRC_DIRECTORY}/log")
target_include_directories(${PROJECT_NAME} PUBLIC utils "${PROJECT_BINARY_DIR}" "${SRC_DIRECTORY}/utils" )
target_include_directories(${PROJECT_NAME} PUBLIC sad_entry "${PROJECT_BINARY_DIR}" "${SRC_DIRECTORY}/sad_entry")
target_include_directories(${PROJECT_NAME} PUBLIC spd_entry "${PROJECT_BINARY_DIR}" "${SRC_DIRECTORY}/spd_entry")                   
target_include_directories(${PROJECT_NAME} PUBLIC parson "${PROJECT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/parson")


# Only include this for the unstrusted binary
if (${TARGET} STREQUAL "untrusted")
    message(STATUS "Target incldue for untrusted")
    target_include_directories(${PROJECT_NAME} PUBLIC pfkeyv2_utils "${PROJECT_BINARY_DIR}" "${SRC_DIRECTORY}/pfkeyv2_utils")
    target_include_directories(${PROJECT_NAME} PUBLIC sysrepo_utils "${PROJECT_BINARY_DIR}" "${SRC_DIRECTORY}/sysrepo_utils")
endif()

if (${TARGET} STREQUAL "untrusted")
    set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "i2nsf_untrusted")
elseif(${TARGET} STREQUAL "enarx")
    set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "i2nsf_enarx")
elseif(${TARGET} STREQUAL "keystone")
    set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "i2nsf_keystone")
else()
    set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "i2nsf_unknown")
endif()



# TODO Add for the untrusted case
# We need to install yang modules
# We need to enable sudo "sysrepoctl -e ikeless-notification -a -c  ietf-i2nsf-ikeless -v3"


# add the binary tree to the search path for include files
target_include_directories(I2NSF PUBLIC
                            "${PROJECT_BINARY_DIR}"
                        )
