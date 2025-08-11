# --- 基本项目设置 ---
cmake_minimum_required(VERSION 3.8)
project(Cpings C)

# --- 全局编译选项 ---
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    add_compile_definitions(_DEBUG)
endif()

add_compile_definitions(_USE_BINARYSEARCH)

# add_compile_definitions(_GNU_SOURCE)
# add_compile_definitions(_POSIX_C_SOURCE=200809L)
add_compile_definitions(_DEFAULT_SOURCE)

# --- 查找依赖库 ---
find_package(Threads REQUIRED)

# ==========================================================
#                  核心库 (Core Library)
# ==========================================================
add_library(cpings_core STATIC
    utils/util.c
    utils/network.c
    utils/dns.c
    utils/scanner.c
    utils/fake.c
)

target_include_directories(cpings_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ==========================================================
#               主要可执行文件 (Main Executables)
# ==========================================================
# src
add_executable(nsmuter src/nsmuter.c)
add_executable(udpscan src/udpscan.c)
add_executable(attack_recur src/attack_recur.c)
add_executable(attack_recur_ns src/attack_recur_ns.c)
add_executable(attack_forwr src/attack_forwr.c)


# test
add_executable(test_ipfragment test/test_ipfragment.c)
add_executable(test_build_fake_resp test/test_build_fake_resp.c)


# --- 链接所有主要的可执行文件到核心库和线程库 ---
set(MAIN_TARGETS
    nsmuter
    udpscan
    attack_recur
    attack_recur_ns
    attack_forwr
    test_ipfragment
    test_build_fake_resp
)

foreach(TARGET ${MAIN_TARGETS})
    target_link_libraries(${TARGET}
        PRIVATE
        cpings_core        # 链接我们的核心库
        ${CMAKE_THREAD_LIBS_INIT} # 链接线程库
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