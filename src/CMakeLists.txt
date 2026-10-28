# SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
# SPDX-License-Identifier: AGPL-3.0-or-later

# relayprotocol.* is also compiled by the KDE Connect desktop client, which pulls this
# repository in as a git submodule. It must keep depending on QtCore and QtNetwork only.
add_library(relayserver_static STATIC
    relayserver.cpp
    relayprotocol.cpp
)
target_include_directories(relayserver_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(relayserver_static PUBLIC Qt6::Core Qt6::Network)

add_executable(kdeconnect-relayserver main.cpp)
target_compile_definitions(kdeconnect-relayserver PRIVATE RELAYSERVER_VERSION="${PROJECT_VERSION}")
target_link_libraries(kdeconnect-relayserver PRIVATE relayserver_static)
set_target_properties(kdeconnect-relayserver PROPERTIES MACOSX_BUNDLE FALSE)

install(TARGETS kdeconnect-relayserver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
