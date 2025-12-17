cmake_minimum_required(VERSION 3.18)
project(Voix VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use LLVM/Clang
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Add LLVM definitions and include directories
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Enable thin LTO
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=thin")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto=thin")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto=thin")

# Find TCMalloc
find_library(TCMALLOC_LIBRARY tcmalloc)
if(TCMALLOC_LIBRARY)
    message(STATUS "Found TCMalloc: ${TCMALLOC_LIBRARY}")
    set(USE_TCMALLOC ON)
else()
    message(WARNING "TCMalloc not found, falling back to system malloc")
    set(USE_TCMALLOC OFF)
endif()

# Source files
set(VOIX_SOURCES
    src/main.cpp
    src/voix.cpp
    src/config.cpp
    src/security.cpp
    src/utils.cpp
    src/pam_auth.cpp
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Create executable
add_executable(voix ${VOIX_SOURCES})

# Link libraries
target_link_libraries(voix ${LLVM_LIBS})
if(USE_TCMALLOC)
    target_link_libraries(voix ${TCMALLOC_LIBRARY})
endif()

# Security hardening flags
target_compile_options(voix PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)

# Install rules
install(TARGETS voix DESTINATION bin)
install(FILES config/voix.conf DESTINATION etc)
install(FILES docs/voix.1 DESTINATION man/man1)

# Testing
enable_testing()
add_subdirectory(tests)
