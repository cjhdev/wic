cmake_minimum_required(VERSION 3.0)
project(wic_client VERSION 1.0.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)

set(CMAKE_CXX_FLAGS "-D__STDC_CONSTANT_MACROS")
IF(MSVC)
    SET(CMAKE_CXX_FLAGS "/EHsc")
		set(CompilerFlags
			CMAKE_CXX_FLAGS
			CMAKE_CXX_FLAGS_DEBUG
			CMAKE_CXX_FLAGS_RELEASE
			CMAKE_C_FLAGS
			CMAKE_C_FLAGS_DEBUG
			CMAKE_C_FLAGS_RELEASE
		)
		foreach(CompilerFlag ${CompilerFlags})
			string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
		endforeach()
ENDIF(MSVC)

set(SOURCE
  examples/demo_client/demo_client.c
  examples/demo_client/port.h
  examples/demo_client/log.h
)

set(SOURCE_LIB
  src/http_parser.c
  src/wic.c
  examples/transport/transport.h
  examples/transport/transport.c
)

if(WIN32)
add_definitions(/DWIN32 /DWIN32_LEAN_AND_MEAN)
endif()

if(WIN32)
set(SYSTEM_LIB
  WS2_32
)
else()
if(APPLE)
set(SYSTEM_LIB
  "-framework Foundation"
  "-framework CoreFoundation"
  "-framework AppKit"
  "-framework IOKit"
  "-framework AVFoundation"
)
else()
set(SYSTEM_LIB
)
endif()
endif()


add_library(${CMAKE_PROJECT_NAME} STATIC ${SOURCE_PROTO} ${SOURCE_LIB})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${SYSTEM_LIB})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE include examples/transport examples/demo_client)

add_executable(${CMAKE_PROJECT_NAME}_bin ${SOURCE})
add_dependencies(${CMAKE_PROJECT_NAME}_bin ${CMAKE_PROJECT_NAME})
target_link_libraries(${CMAKE_PROJECT_NAME}_bin PRIVATE ${CMAKE_PROJECT_NAME})
target_include_directories(${CMAKE_PROJECT_NAME}_bin PRIVATE include examples/transport examples/demo_client)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC" AND CMAKE_BUILD_TYPE MATCHES "Release")
  target_compile_options(${CMAKE_PROJECT_NAME}_bin PRIVATE /Zi)
  set_target_properties(${CMAKE_PROJECT_NAME}_bin PROPERTIES 
    LINK_FLAGS "/INCREMENTAL:NO /DEBUG /OPT:REF /OPT:ICF"
  )
  set_target_properties(${CMAKE_PROJECT_NAME}_bin PROPERTIES 
    COMPILE_PDB_NAME ${CMAKE_PROJECT_NAME}
    COMPILE_PDB_OUTPUT_DIR ${CMAKE_BINARY_DIR}
  )
endif()

set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT "${CMAKE_PROJECT_NAME}_bin")
