# --- 基本项目设置 ---
cmake_minimum_required(VERSION 3.8)
project(Cpings C)

# --- 全局编译选项 ---
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
# set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    add_compile_definitions(_DEBUG)
endif()

add_compile_definitions(_USE_BINARYSEARCH)

# add_compile_definitions(_GNU_SOURCE)
# add_compile_definitions(_POSIX_C_SOURCE=200809L)
# add_compile_definitions(_DEFAULT_SOURCE)

# --- 查找依赖库 ---
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)

# ==========================================================
#                  核心库 (Core Library)
# ==========================================================
add_library(cpings_core STATIC
    utils/util.c
    utils/network.c
    utils/dns.c
    utils/scanner.c
    utils/fake.c
    utils/sender.c
    utils/strategy.c
)

target_include_directories(cpings_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ==========================================================
#               主要可执行文件 (Main Executables)
# ==========================================================
# src
add_executable(udpscan src/udpscan.c)
add_executable(saddns src/saddns_attack.c)
add_executable(saddns_l src/saddns_attack_lower.c)

# test
add_executable(test_ipfragment test/test_ipfragment.c)
add_executable(test_build_fake_resp test/test_build_fake_resp.c)
add_executable(test_sender test/test_sender.c)
add_executable(test_pps_sender test/test_pps_sender.c)
add_executable(test_burst_sender test/test_burst_sender.c)
add_executable(test_multitask_sender test/test_multitask_sender.c)
add_executable(test_multitask_limit_sender test/test_multitask_limit_sender.c)


# --- 链接所有主要的可执行文件到核心库和线程库 ---
set(MAIN_TARGETS
    saddns
    saddns_l
    udpscan
    test_ipfragment
    test_build_fake_resp
    test_sender
    test_pps_sender
    test_burst_sender
    test_multitask_sender
    test_multitask_limit_sender
)

foreach(TARGET ${MAIN_TARGETS})
    target_link_libraries(${TARGET}
        PRIVATE
        cpings_core        # 链接我们的核心库
        ${CMAKE_THREAD_LIBS_INIT} # 链接线程库
        ${LIBUV_LIBRARIES}         # 链接 libuv 库
    )
    target_include_directories(${TARGET}
        PRIVATE
        ${LIBUV_INCLUDE_DIRS}      # 添加 libuv 的头文件路径
    )
endforeach()


# ==========================================================
#                  测试部分
# ==========================================================

# enable_testing()

# # 假设你想将 test_ipfragment 作为 CTest 的一个测试用例
# add_test(
#     NAME IP_Fragmentation_Test
#     COMMAND test_ipfragment # CTest 会执行这个可执行文件
# )