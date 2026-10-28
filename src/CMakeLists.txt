# SPDX-FileCopyrightText: 2026 KDE Connect contributors
# SPDX-License-Identifier: BSD-3-Clause

# Only depends on QtCore and QtNetwork so it can be deployed on a headless server
add_library(kdeconnectrelayserver_static STATIC
    relayserver.cpp
    ${PROJECT_SOURCE_DIR}/core/backends/relay/relayprotocol.cpp
)
target_include_directories(kdeconnectrelayserver_static PUBLIC ${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kdeconnectrelayserver_static PUBLIC Qt::Core Qt::Network)

add_executable(kdeconnect-relayserver main.cpp)
target_link_libraries(kdeconnect-relayserver kdeconnectrelayserver_static)

install(TARGETS kdeconnect-relayserver ${KDECONNECT_INSTALL_TARGETS_DEFAULT_ARGS})
