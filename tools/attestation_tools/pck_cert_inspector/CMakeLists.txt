# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

list(APPEND SOURCES main.c)

add_executable(pck_cert_inspector ${SOURCES})

target_link_libraries(pck_cert_inspector oehost)

# assemble into proper collector dir
set_property(TARGET pck_cert_inspector PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS pck_cert_inspector EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
