FetchContent_Declare(unicode_xml_database
	URL https://www.unicode.org/Public/15.1.0/ucdxml/ucd.nounihan.flat.zip
	URL_HASH SHA256=48d7165829782833a619db2c06146f2790cafd6061336382175b5d8bc145a9eb
)

FetchContent_MakeAvailable(unicode_xml_database)

add_custom_command(
	OUTPUT unicode.hpp
	COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/construct_unicode_database.py" --xml-database "${unicode_xml_database_SOURCE_DIR}/ucd.nounihan.flat.xml" --output "unicode.hpp"
	DEPENDS "${unicode_xml_database_SOURCE_DIR}/ucd.nounihan.flat.xml" "${CMAKE_CURRENT_SOURCE_DIR}/construct_unicode_database.py"
	VERBATIM
)

add_library(unicode INTERFACE unicode.hpp)
target_include_directories(unicode INTERFACE "${CMAKE_CURRENT_BINARY_DIR}")
