# SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.22)

project(kdeconnect-relayserver VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

include(GNUInstallDirs)
include(CTest)

option(INSTALL_SYSTEMD_UNIT "Install the systemd unit" ON)
# CMAKE_INSTALL_LIBDIR is multiarch on Debian (lib/x86_64-linux-gnu), where systemd does not look
set(SYSTEMD_UNIT_DIR "lib/systemd/system" CACHE STRING "Directory for the systemd unit, relative to the install prefix or absolute")

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network)
if(BUILD_TESTING)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
endif()

add_compile_definitions(
    QT_NO_CAST_FROM_ASCII
    QT_NO_CAST_TO_ASCII
    QT_NO_URL_CAST_FROM_STRING
    QT_NO_KEYWORDS
)

add_subdirectory(src)

if(INSTALL_SYSTEMD_UNIT)
    configure_file(packaging/systemd/kdeconnect-relayserver.service.in kdeconnect-relayserver.service @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kdeconnect-relayserver.service DESTINATION ${SYSTEMD_UNIT_DIR})
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
