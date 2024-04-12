#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
from more_itertools import consecutive_groups
from typing import Iterable
import sys
import os

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

def code_points_satisfying(property_name: str, code_points: Iterable[ET.Element], condition) -> str:
	matching_code_points = []

	for c in code_points:
		if condition(c):
			if c.get("cp") is not None:
				matching_code_points.append(int(c.get("cp"), 16))
			elif c.get("first-cp") is not None and c.get("last-cp") is not None:
				matching_code_points.extend(
					range(int(c.get("first-cp"), 16), int(c.get("last-cp"), 16) + 1)
				)

	ranges = [list(g) for g in consecutive_groups(matching_code_points)]

	ret = f"template <>\n"
	ret += f"[[nodiscard]] constexpr bool has_property<{property_name}>(const code_point c) noexcept {{\n"

	ret += f"\tstatic constexpr std::array<code_point_range, {len(ranges)}> code_point_ranges {{{{\n"
	for r in ranges:
		ret += f"\t\t{{0x{r[0]:06X}, 0x{r[-1]:06X}}},\n"
	ret += f"\t}}}};\n\n"

	ret += f"\treturn std::binary_search(std::cbegin(code_point_ranges), std::cend(code_point_ranges), c);\n"
	ret += f"}}"

	return ret

def main() -> None:
	args = parse_command_line_arguments()
	xml_root = ET.parse(args.xml_database).getroot()
	code_points = xml_root.find("{http://www.unicode.org/ns/2003/ucd/1.0}repertoire").findall("{http://www.unicode.org/ns/2003/ucd/1.0}char")

	args.output.write(f"""\
// SPDX-License-Identifier: Unlicense

// This file was automatically generated by {os.path.basename(__file__)}. Do not edit it directly!

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>

namespace unicode {{

using code_point = std::uint32_t;

/// A closed range of code points.
struct code_point_range final {{
	code_point lower_bound;
	code_point upper_bound;
}};

constexpr bool operator <(const code_point c, const code_point_range& r) noexcept {{
	return c < r.lower_bound;
}}

constexpr bool operator <(const code_point_range& r, const code_point c) noexcept {{
	return c > r.upper_bound;
}}

enum class binary_property : std::uint32_t {{
	xid_start,
	xid_continue,
	end_of_line,
	ignorable_format_control,
	horizontal_space,
}};

template <binary_property property>
[[nodiscard]] constexpr bool has_property(code_point) noexcept = delete;

{code_points_satisfying(
	"binary_property::xid_start",
	code_points,
	lambda c: c.get("XIDS") == "Y" or c.get("ID_Compat_Math_Start") == "Y" or c.get("na") in ["LOW LINE"]
)}

{code_points_satisfying(
	"binary_property::xid_continue",
	code_points,
	lambda c: c.get("XIDC") == "Y" or c.get("ID_Compat_Math_Continue") == "Y"
)}

// https://www.unicode.org/reports/tr31/#Whitespace_and_Syntax
{code_points_satisfying(
	"binary_property::end_of_line",
	code_points,
	lambda c: c.get("cp") in [
		"000A",
		"000B",
		"000C",
		"000D",
		"0085",
		"2028",
		"2029",
	]
)}

{code_points_satisfying(
	"binary_property::ignorable_format_control",
	code_points,
	lambda c: c.get("Pat_WS") == "Y" and c.get("DI") == "Y"
)}

{code_points_satisfying(
	"binary_property::horizontal_space",
	code_points,
	lambda c: c.get("Pat_WS") == "Y" and c.get("DI") == "N" and c.get("cp") not in [
		"000A",
		"000B",
		"000C",
		"000D",
		"0085",
		"2028",
		"2029",
	]
)}

}} // namespace unicode
""")

if __name__ == "__main__":
	main()
