cmake_minimum_required(VERSION 3.16)
project(FirewallSystem CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── Npcap / WinPcap SDK paths ───────────────────────────────────────────────
# Download Npcap SDK from https://npcap.com/#download
# Extract the SDK and point CMake at the directory, or set NPCAP_SDK_DIR.
if(NOT DEFINED NPCAP_SDK_DIR OR NPCAP_SDK_DIR STREQUAL "")
    if(DEFINED ENV{NPCAP_SDK_DIR})
        set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
    elseif(EXISTS "${CMAKE_SOURCE_DIR}/npcap-sdk/Include/pcap.h")
        set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk")
    elseif(EXISTS "C:/npcap-sdk/Include/pcap.h")
        set(NPCAP_SDK_DIR "C:/npcap-sdk")
    elseif(DEFINED ENV{USERPROFILE} AND EXISTS "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16/Include/pcap.h")
        set(NPCAP_SDK_DIR "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16")
    endif()
endif()
set(NPCAP_SDK_DIR "${NPCAP_SDK_DIR}" CACHE PATH "Path to Npcap SDK")

find_path(NPCAP_INCLUDE_DIR
    NAMES pcap.h
    PATHS
        "${NPCAP_SDK_DIR}/Include"
        "${NPCAP_SDK_DIR}/include"
        "C:/npcap-sdk/Include"
        "C:/Program Files/Npcap/Include"
        "C:/Program Files (x86)/Npcap/Include"
        "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16/Include"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NPCAP_LIB_DIRS
        "${NPCAP_SDK_DIR}/Lib/x64"
        "${NPCAP_SDK_DIR}/Lib"
        "C:/npcap-sdk/Lib/x64"
        "C:/npcap-sdk/Lib"
        "C:/Program Files/Npcap/Lib/x64"
        "C:/Program Files/Npcap/Lib"
    )
else()
    set(NPCAP_LIB_DIRS
        "${NPCAP_SDK_DIR}/Lib"
        "C:/npcap-sdk/Lib"
        "C:/Program Files/Npcap/Lib"
    )
endif()

find_library(WPCAP_LIB
    NAMES wpcap
    PATHS ${NPCAP_LIB_DIRS}
)
find_library(PACKET_LIB
    NAMES Packet
    PATHS ${NPCAP_LIB_DIRS}
)

if(NOT NPCAP_INCLUDE_DIR OR NOT WPCAP_LIB OR NOT PACKET_LIB)
    message(FATAL_ERROR
        "Npcap SDK not found or incomplete.\n"
        "Set -DNPCAP_SDK_DIR=<path-to-npcap-sdk> or define the environment variable NPCAP_SDK_DIR.\n"
        "Expected include file: pcap.h and libraries: wpcap.lib, Packet.lib.\n"
        "Sample paths: C:/npcap-sdk, ${CMAKE_SOURCE_DIR}/npcap-sdk")
endif()

# ─── Source files ────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    src/DateTimeUtility.cpp
    src/NetworkAddress.cpp
    src/FirewallRule.cpp
    src/StatefulFirewallRule.cpp
    src/FirewallLogEntry.cpp
    src/FirewallStatistics.cpp
    src/ConnectionTracker.cpp
    src/FileManager.cpp
    src/NetworkPacket.cpp
    src/LogManager.cpp
    src/WindowsFirewallManager.cpp
    src/FirewallEngine.cpp
    src/PacketSniffer.cpp
)

add_executable(firewall_system ${SOURCES})

# ─── Include directories ─────────────────────────────────────────────────────
target_include_directories(firewall_system PRIVATE
    ${NPCAP_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

# ─── Libraries ───────────────────────────────────────────────────────────────
target_link_libraries(firewall_system PRIVATE
    ${WPCAP_LIB}    # Npcap/WinPcap capture library
    ${PACKET_LIB}   # Npcap packet driver
    ws2_32          # Winsock
    ole32           # COM
    oleaut32        # COM automation
)

# ─── Windows-specific compiler flags ─────────────────────────────────────────
if(MSVC)
    target_compile_definitions(firewall_system PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        HAVE_REMOTE          # required by Npcap for remote capture support
        _CRT_SECURE_NO_WARNINGS
    )
    target_compile_options(firewall_system PRIVATE /W3 /MP)
    # Request Administrator privileges in the manifest
    set_target_properties(firewall_system PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

# ─── Output ──────────────────────────────────────────────────────────────────
set_target_properties(firewall_system PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin/Release"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/bin/RelWithDebInfo"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/bin/MinSizeRel"
)

message(STATUS "Npcap SDK dir     : ${NPCAP_SDK_DIR}")
message(STATUS "Npcap include dir : ${NPCAP_INCLUDE_DIR}")
message(STATUS "Npcap wpcap lib   : ${WPCAP_LIB}")
message(STATUS "Npcap packet lib  : ${PACKET_LIB}")
message(STATUS "Build type        : ${CMAKE_BUILD_TYPE}")
