# SPDX-License-Identifier: Unlicense

add_subdirectory(unicode)

add_executable(incc)

target_sources(incc
	PRIVATE
		main.cpp
)

target_link_libraries(incc PRIVATE unicode)
