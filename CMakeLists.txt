# SPDX-License-Identifier: Apache-2.0

set(BOARD nrf52840dk_nrf52840)   # DK

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(central)

add_compile_options(-Wall)

target_sources(app PRIVATE
  src/main.c
)

zephyr_library_include_directories(${ZEPHYR_BASE}/samples/bluetooth)
