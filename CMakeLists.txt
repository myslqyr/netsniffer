cmake_minimum_required(VERSION 3.16)

project(netsniffer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

add_executable(netsniffer-capture src/helper/main.cpp)
set_target_properties(netsniffer-capture PROPERTIES AUTOMOC OFF)
target_link_libraries(netsniffer-capture PRIVATE PkgConfig::PCAP)
target_compile_options(netsniffer-capture PRIVATE -Wall -Wextra -Wpedantic)

add_library(packet_parser STATIC src/parser/packetparser.cpp)
set_target_properties(packet_parser PROPERTIES AUTOMOC OFF)
target_link_libraries(packet_parser PUBLIC Qt6::Core PRIVATE PkgConfig::PCAP)
target_include_directories(packet_parser PUBLIC src)
target_compile_options(packet_parser PRIVATE -Wall -Wextra -Wpedantic)

add_executable(netsniffer
    src/main.cpp
    src/capture/device.cpp
    src/capture/captureworker.cpp
    src/ui/mainwindow.cpp
    src/ui/packetbytesview.cpp
)
target_link_libraries(netsniffer PRIVATE Qt6::Widgets PkgConfig::PCAP packet_parser)
target_compile_options(netsniffer PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
    add_executable(parser_check tests/parser_check.cpp)
    set_target_properties(parser_check PROPERTIES AUTOMOC OFF)
    target_link_libraries(parser_check PRIVATE packet_parser)
    target_compile_options(parser_check PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME packet_parser COMMAND parser_check)
    add_executable(fake_capture_helper tests/fake_capture_helper.cpp)
    set_target_properties(fake_capture_helper PROPERTIES AUTOMOC OFF)
    target_include_directories(fake_capture_helper PRIVATE src)
    target_compile_options(fake_capture_helper PRIVATE -Wall -Wextra -Wpedantic)
    add_executable(capture_ipc_check tests/capture_ipc_check.cpp src/capture/captureworker.cpp)
    target_link_libraries(capture_ipc_check PRIVATE Qt6::Core)
    target_include_directories(capture_ipc_check PRIVATE src)
    target_compile_options(capture_ipc_check PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME capture_ipc COMMAND capture_ipc_check $<TARGET_FILE:fake_capture_helper>)
    set_tests_properties(capture_ipc PROPERTIES TIMEOUT 30)
    add_executable(capture_ui_check tests/capture_ui_check.cpp
        src/ui/mainwindow.cpp src/ui/packetbytesview.cpp src/capture/captureworker.cpp)
    target_link_libraries(capture_ui_check PRIVATE Qt6::Widgets packet_parser)
    target_include_directories(capture_ui_check PRIVATE src)
    target_compile_options(capture_ui_check PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME capture_ui COMMAND capture_ui_check $<TARGET_FILE:fake_capture_helper>)
    set_tests_properties(capture_ui PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
    add_executable(packet_details_check tests/packet_details_check.cpp
        src/ui/mainwindow.cpp src/ui/packetbytesview.cpp src/capture/captureworker.cpp)
    target_link_libraries(packet_details_check PRIVATE Qt6::Widgets packet_parser)
    target_include_directories(packet_details_check PRIVATE src)
    target_compile_options(packet_details_check PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME packet_details COMMAND packet_details_check $<TARGET_FILE:fake_capture_helper>)
    set_tests_properties(packet_details PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 45)
    add_executable(capture_check tests/capture_check.cpp src/capture/captureworker.cpp)
    target_link_libraries(capture_check PRIVATE Qt6::Core)
    target_include_directories(capture_check PRIVATE src)
    target_compile_options(capture_check PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME capture_open_error COMMAND capture_check --expect-error
        --helper $<TARGET_FILE:netsniffer-capture>)
endif()
