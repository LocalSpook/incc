#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
import pathlib

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
		required=True,
		type=argparse.FileType("w+", encoding="utf-8"),
		help="C++ header file to write the database to."
	)
	return parser.parse_args()

def main() -> None:
	args = parse_command_line_arguments()
	code_points = ET.parse(args.xml_database).getroot()

	args.output.write("""\
// SPDX-License-Identifier: Unlicense

#pragma once

#include <array>

namespace unicode {

} // namespace unicode
""")

if __name__ == "__main__":
	main()
