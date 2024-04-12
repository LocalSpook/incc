# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(incompetent
	VERSION 1.0.0
	LANGUAGES CXX
)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)

add_subdirectory(src)
