#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
from more_itertools import consecutive_groups
from typing import Iterable, Callable
import sys
import itertools
import os
from dataclasses import dataclass

UNICODE_XML_NAMESPACE = { "": "http://www.unicode.org/ns/2003/ucd/1.0" }

def parse_command_line_arguments():
	parser = argparse.ArgumentParser(
		description="Construct a C++ Unicode database from the official XML database."
	)
	parser.add_argument(
		"-d", "--xml-database",
		required=True,
		type=argparse.FileType("r", encoding="utf-8"),
		help="Path to the Unicode XML database."
	)
	parser.add_argument(
		"-o", "--output",
		type=argparse.FileType("w+", encoding="utf-8"),
		default=sys.stdout,
		help="C++ header file to write the database to."
	)
	return parser.parse_args()

def all_code_points(xml_database_root: Iterable[ET.Element]) -> Iterable[ET.Element]:
	for child in xml_database_root.find("repertoire", UNICODE_XML_NAMESPACE):
		if child.get("cp") is not None:
			yield child
		elif child.tag not in ["{http://www.unicode.org/ns/2003/ucd/1.0}surrogate"]:
			for c in range(int(child.get("first-cp"), 16), int(child.get("last-cp"), 16) + 1):
				element = ET.Element(child.tag, child.attrib)
				element.set("cp", f"{c:04X}")
				element.set("first-cp", None)
				element.set("last-cp", None)
				yield element

def code_points_satisfying(property_name: str, code_points: Iterable[ET.Element], condition: Callable) -> str:
	matching_code_points = [int(c.get("cp"), 16) for c in code_points if condition(c)]
	ranges = [list(g) for g in consecutive_groups(matching_code_points)]

	ret = f"template <>\n"
	ret += f"[[nodiscard]] constexpr bool has_property<{property_name}>(const char32_t c) noexcept {{\n"
	ret += f"\tASSERT_OR_ASSUME_CODE_POINT_IS_VALID(c);\n\n"

	ret += f"\tstatic constexpr std::array<code_point_range, {len(ranges)}> code_point_ranges {{{{\n"
	for r in ranges:
		ret += f"\t\t{{0x{r[0]:06X}, 0x{r[-1]:06X}}},\n"
	ret += f"\t}}}};\n\n"

	ret += f"\treturn std::binary_search(std::cbegin(code_point_ranges), std::cend(code_point_ranges), c);\n"
	ret += f"}}"

	return ret

def binary_properties(xml_root: ET.Element, properties: dict[str, Callable]) -> str:
	ret = f"enum class binary_property : std::uint32_t {{\n"
	for name in properties:
		ret += f"\t{name},\n"
	ret += f"}};\n\n"

	ret += """\
template <binary_property property>
[[nodiscard]] constexpr bool has_property(char32_t) noexcept = delete;
"""

	for name, condition in properties.items():
		ret += f"\n{code_points_satisfying(f"binary_property::{name}", all_code_points(xml_root), condition)}\n"

	return ret

@dataclass
class CodePointAge:
	major: str
	minor: str
	code_point: int

def age(code_points: Iterable[ET.Element]) -> str:
	ret = f"""\
[[nodiscard]] constexpr std::optional<std::pair<std::uint8_t, std::uint8_t>> age(const char32_t c) noexcept {{
	ASSERT_OR_ASSUME_CODE_POINT_IS_VALID(c);

	struct compact_code_point_range_and_version final {{
		bool assigned : 1;
		std::uint8_t version_major : 5;
		std::uint8_t version_minor : 5;
		char32_t upper_bound : 21;
	}};

	static_assert(sizeof(compact_code_point_range_and_version) <= 4);
"""

	ages = []
	for c in code_points:
		if "." in c.get("age"):
			major, minor = c.get("age").split(".")
		else:
			major, minor = None, None

		ages.append(CodePointAge(major, minor, int(c.get("cp"), 16)))
	ranges = [list(g) for g in itertools.groupby(ages)]

	ret += f"\tstatic constexpr std::array<compact_code_point_range_and_version, {len(ranges)}> code_point_ranges {{{{\n"
	for r in ranges:
		ret += f"\t\t{{}},\n"
	ret += f"}}}};\n\n"

	ret += f"""\
	const auto age {{std::lower_bound(std::cbegin(code_point_ranges), std::cend(code_point_ranges), c, [] (const compact_code_point_range_and_version& r, const char32_t c) noexcept {{ return c > r.upper_bound; }})}};
	return age->assigned ? std::optional<std::pair<std::uint8_t, std::uint8_t>> {{{{age->version_major, age->version_minor}}}} : std::nullopt;
}}"""

	return ret

def taiwan_telegraph_codes(code_points: Iterable[ET.Element]) -> str:
	codes = []

	for c in code_points:
		if c.get("kTaiwanTelegraph") is not None:
			codes.append((int(c.get("cp"), 16), int(c.get("kTaiwanTelegraph").split(" ")[0], 10)))

	ret = f"\tstatic constexpr std::array<std::uint32_t, {len(codes)}> telegraph_code_dictionary {{\n"
	for code_point, code in codes:
		ret += f"\t\t0x{code:04X}U | (0x{code_point:06X}U << telegraph_code_bits),\n"
	ret += f"\t}};"

	return ret

def english_glosses(code_points):
	definitions = []

	for c in code_points:
		if c.get("kDefinition") is not None:
			definitions.append((int(c.get("cp"), 16), c.get("kDefinition")))

	ret = f"\tstatic constexpr std::array<std::uint32_t, {len(definitions)}> definition_dictionary {{\n"
	for code_point, code in definitions:
		pass
		# ret += f"\t\t{{}},\n"
	ret += f"\t}};"

	return ret

def main() -> None:
	args = parse_command_line_arguments()
	xml_root = ET.parse(args.xml_database).getroot()

	args.output.write(f"""\
// SPDX-License-Identifier: Unlicense

// This file was automatically generated by {os.path.basename(__file__)}. Do not edit it directly!

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <cassert>

#ifndef NDEBUG

#define ASSERT_OR_ASSUME_CODE_POINT_IS_VALID(c) \\
	if consteval {{                              \\
		if (c > 0x10FFFF) {{          \\
			assert(false && "Code point exceeds maximum code point size.");     \\
		}}                                       \\
		if (c >= 0xD800 && c <= 0xDFFF) {{          \\
			assert(false && "Received an undecoded surrogate code point.");     \\
		}}                                       \\
	}} else {{                                    \\
		assert(c <= 0x10FFFF && "Code point exceeds maximum code point size.");         \\
		assert(c < 0xD800 || c > 0xDFFF && "Received an undecoded surrogate code point.");     \\
	}}

#else

#define ASSERT_OR_ASSUME_CODE_POINT_IS_VALID(c) \\
	if consteval {{                              \\
		if (c > 0x10FFFF) {{          \\
			assert(false && "Code point exceeds maximum code point size.");     \\
		}}                                       \\
		if (c >= 0xD800 && c <= 0xDFFF) {{          \\
			assert(false && "Received an undecoded surrogate code point.");     \\
		}}                                       \\
	}} else {{                                    \\
		[[assume(c <= 0x10FFFF)]];     \\
		[[assume(c < 0xD800 || c > 0xDFFF)]];     \\
	}}

#endif

namespace uni {{

inline constexpr std::uint8_t unicode_version_major {{{xml_root.find("description", UNICODE_XML_NAMESPACE).text.split(" ")[1].split(".")[0]}}};
inline constexpr std::uint8_t unicode_version_minor {{{xml_root.find("description", UNICODE_XML_NAMESPACE).text.split(" ")[1].split(".")[1]}}};

[[nodiscard]] constexpr bool is_valid_code_point(const char32_t c) noexcept {{
	static constexpr char32_t maximum_code_point_value {{0x10FFFF}};
	static constexpr char32_t surrogate_range_start {{0xD800}};
	static constexpr char32_t surrogate_range_end {{0xDFFF}};

	return c <= maximum_code_point_value && (c < surrogate_range_start || c > surrogate_range_end);
}}

/// A closed range of code points.
struct code_point_range final {{
	char32_t lower_bound;
	char32_t upper_bound;
}};

constexpr bool operator <(const char32_t c, const code_point_range& r) noexcept {{
	return c < r.lower_bound;
}}

constexpr bool operator <(const code_point_range& r, const char32_t c) noexcept {{
	return c > r.upper_bound;
}}

{binary_properties(xml_root, {
	"xid_start": lambda c: c.get("XIDS") == "Y" or c.get("ID_Compat_Math_Start") == "Y" or c.get("na") in ["LOW LINE"],
	"xid_continue": lambda c: c.get("XIDC") == "Y" or c.get("ID_Compat_Math_Continue") == "Y",
	# https://www.unicode.org/reports/tr31/#Whitespace_and_Syntax
	"end_of_line": lambda c: c.get("cp") in [
		"000A",
		"000B",
		"000C",
		"000D",
		"0085",
		"2028",
		"2029",
	],
	"ignorable_format_control": lambda c: c.get("Pat_WS") == "Y" and c.get("DI") == "Y",
	"horizontal_space": lambda c: c.get("Pat_WS") == "Y" and c.get("DI") == "N" and c.get("cp") not in [
		"000A",
		"000B",
		"000C",
		"000D",
		"0085",
		"2028",
		"2029",
	],
	"deprecated": lambda c: c.get("Dep") == "Y",
	"default_ignorable": lambda c: c.get("DI") == "Y",
})}

{age(all_code_points(xml_root))}

namespace han {{

/// Unihan property kTaiwanTelegraph.
///
/// @note A few code points have multiple corresponding telegraph codes. This function only returns one of them.
[[nodiscard]] constexpr std::optional<std::uint16_t> taiwan_telegraph_code(const char32_t c) noexcept {{
	ASSERT_OR_ASSUME_CODE_POINT_IS_VALID(c);

	// Here we do backflips to make the dictionary entries fit into 32 bits.
	// Each dictionary entry looks like: {{ code_point: 18; telegraph_code: 14; }}

	static constexpr std::size_t telegraph_code_bits {{14}};

{taiwan_telegraph_codes(all_code_points(xml_root))}

	const auto lower_bound {{std::lower_bound(std::cbegin(telegraph_code_dictionary), std::cend(telegraph_code_dictionary), c, [] (const std::uint32_t entry, const char32_t c) noexcept {{ return c > (entry >> telegraph_code_bits); }})}};
	return (lower_bound != std::cend(telegraph_code_dictionary) && c == (*lower_bound >> telegraph_code_bits)) ? std::optional<std::uint16_t>(*lower_bound & ((1 << telegraph_code_bits) - 1)) : std::nullopt;
}}

/// An English definition for this character. Unihan property kDefiniton.
///
/// @note The returned std::string_view is null-terminated.
[[nodiscard]] constexpr std::optional<std::string_view> english_gloss(const char32_t c) noexcept {{
	ASSERT_OR_ASSUME_CODE_POINT_IS_VALID(c);

	struct gloss_entry final {{
		const char * definition;
		std::uint16_t length;
		std::uint16_t code_point;
	}};

{english_glosses(all_code_points(xml_root))}

	static_assert(
		std::find_if(std::cbegin(gloss_dictionary), std::cend(gloss_dictionary), [] (const auto& entry) {{ return entry.second[std::size(entry.second)] != '\\0'; }}) == std::cend(gloss_dictionary),
		"Dictionary entry is missing a null terminator!"
	);

	const auto entry {{std::lower_bound(std::cbegin(gloss_dictionary), std::cend(gloss_dictionary), c, [] (const gloss_entry& e, const char32_t c) noexcept {{ return c > e.code_point; }})}};
	return (entry != std::cend(gloss_dictionary)) ? std::optional<std::string_view> {{{{entry->definition, entry->length}}}} : std::nullopt;
}}

}} // namespace han

}} // namespace uni
""")

if __name__ == "__main__":
	main()
