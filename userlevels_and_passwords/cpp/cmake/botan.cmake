cmake_minimum_required(VERSION 3.16)

include(FetchContent)
macro(UseBotan VERSION MODULES)
  if(NOT((${VERSION} EQUAL "2") OR (${VERSION} EQUAL "3")))
    message(FATAL_ERROR "only botan version 2 or 3 is supported")
  endif()

  find_package (Python REQUIRED COMPONENTS Interpreter)

  FetchContent_Declare(
    botan_upstream
    GIT_REPOSITORY https://github.com/randombit/botan.git
    GIT_TAG release-${VERSION}
    GIT_SHALLOW TRUE
  )
  # Check if population has already been performed
  FetchContent_GetProperties(botan_upstream)
  if(NOT botan_upstream_POPULATED)
    # Fetch the content using previously declared details
    message("-- fetch botan_upstream")
    FetchContent_Populate(botan_upstream)
    message("-- fetch botan_upstream - done")

    # Do custom configuration and preparations for cmake
    string(TOLOWER ${CMAKE_CXX_COMPILER_ID} BOTAN_COMPILER_ID)
    if (BOTAN_COMPILER_ID STREQUAL "gnu")
      set(BOTAN_COMPILER_ID "gcc")
    endif()
    if (MINGW)
      set(BOTAN_OS "--os=mingw")
    else()
      set(BOTAN_OS "")
    endif()

    execute_process(COMMAND ${Python_EXECUTABLE}
      ${botan_upstream_SOURCE_DIR}/configure.py
      --quiet
      --cc=${BOTAN_COMPILER_ID}
      ${BOTAN_OS}
      --amalgamation
      --minimized-build
      --enable-modules=${MODULES}
      --build-targets=static
      WORKING_DIRECTORY ${botan_upstream_SOURCE_DIR}
      RESULT_VARIABLE CONFIG_RESULT)
      if(NOT CONFIG_RESULT EQUAL "0")
        message(FATAL_ERROR "configure.py failed with ${CONFIG_RESULT}")
      endif()

    file(WRITE ${botan_upstream_SOURCE_DIR}/CMakeLists.txt
      "cmake_minimum_required(VERSION 3.16)\n"
      "\n"
      "project(botan)\n"
      "\n"
      "add_library(botan STATIC\n"
      "  ${botan_upstream_SOURCE_DIR}/botan_all.h\n"
      "  ${botan_upstream_SOURCE_DIR}/botan_all.cpp\n"
      ")\n"
      "target_include_directories(botan PUBLIC ${botan_upstream_SOURCE_DIR})\n"
      "set_target_properties(botan PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)\n")

    # Bring the populated content into the build
    add_subdirectory(${botan_upstream_SOURCE_DIR} ${botan_upstream_BINARY_DIR})
  endif()
endmacro()
