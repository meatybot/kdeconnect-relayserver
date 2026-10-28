# SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
# SPDX-License-Identifier: AGPL-3.0-or-later

# Only depends on QtCore and QtNetwork so it can be deployed on a headless server
add_library(kdeconnectrelayserver_static STATIC
    relayserver.cpp
    ${PROJECT_SOURCE_DIR}/core/backends/relay/relayprotocol.cpp
)
target_include_directories(kdeconnectrelayserver_static PUBLIC ${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kdeconnectrelayserver_static PUBLIC Qt::Core Qt::Network)

add_executable(kdeconnect-relayserver main.cpp)
target_link_libraries(kdeconnect-relayserver kdeconnectrelayserver_static)
set_target_properties(kdeconnect-relayserver PROPERTIES MACOSX_BUNDLE FALSE)

install(TARGETS kdeconnect-relayserver ${KDECONNECT_INSTALL_TARGETS_DEFAULT_ARGS})
