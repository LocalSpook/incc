FetchContent_Declare(unicode_xml_database
	URL https://www.unicode.org/Public/15.1.0/ucdxml/ucd.all.flat.zip
	URL_HASH SHA256=4fa0757333d59c51eccc2350015a49f3dc39b3c8037316439f4638e1d32a30e6
)

FetchContent_MakeAvailable(unicode_xml_database)

add_custom_command(
	OUTPUT unicode.hpp
	COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/construct_unicode_database.py" --xml-database "${unicode_xml_database_SOURCE_DIR}/ucd.all.flat.zip" --output "unicode.hpp"
	DEPENDS "${unicode_xml_database_SOURCE_DIR}/ucd.all.flat.zip" "${CMAKE_CURRENT_SOURCE_DIR}/construct_unicode_database.py"
	VERBATIM
)

add_library(unicode INTERFACE unicode.hpp)
target_include_directories(unicode INTERFACE "${CMAKE_CURRENT_BINARY_DIR}")
