// SPDX-License-Identifier: Unlicense

#include <exception>
#include <print>

#include "unicode.hpp"

int main() try {
	std::println("Hello world!");
	return 0;
} catch (const std::exception& e) {
	try {
		std::println("Exception: {}", e.what());
	} catch (...) {
		return 1;
	}
	return 1;
} catch (...) {
	return 1;
}
