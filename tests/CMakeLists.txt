# SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
# SPDX-License-Identifier: AGPL-3.0-or-later

add_executable(relayservertest relayservertest.cpp)
target_link_libraries(relayservertest PRIVATE relayserver_static Qt6::Test)
add_test(NAME relayservertest COMMAND relayservertest)
set_tests_properties(relayservertest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 300)

# Command line handling of the installed binary
add_test(NAME cli-version COMMAND kdeconnect-relayserver --version)
set_tests_properties(cli-version PROPERTIES PASS_REGULAR_EXPRESSION "kdeconnect-relayserver ${PROJECT_VERSION}")

add_test(NAME cli-requires-cert COMMAND kdeconnect-relayserver)
set_tests_properties(cli-requires-cert PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli-rejects-bad-port
         COMMAND kdeconnect-relayserver --cert ${CMAKE_CURRENT_SOURCE_DIR}/data/server.crt --key ${CMAKE_CURRENT_SOURCE_DIR}/data/server.key --port 70000)
set_tests_properties(cli-rejects-bad-port PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli-rejects-bad-key
         COMMAND kdeconnect-relayserver --cert ${CMAKE_CURRENT_SOURCE_DIR}/data/server.crt --key ${CMAKE_CURRENT_SOURCE_DIR}/data/server.crt)
set_tests_properties(cli-rejects-bad-key PROPERTIES WILL_FAIL TRUE)
