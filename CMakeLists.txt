cmake_minimum_required(VERSION 3.18)
project(Voix VERSION 2.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)
pkg_check_modules(LUA QUIET lua5.4 lua)

# Source files
set(VOIX_SOURCES
    src/main.cpp
    src/voix.cpp
    src/security.cpp
    src/utils.cpp
    src/lua_config.cpp
    src/config.cpp
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${PAM_INCLUDE_DIRS})
if(LUA_FOUND)
    include_directories(${LUA_INCLUDE_DIRS})
endif()

# Create executable
add_executable(voix ${VOIX_SOURCES})

# Link libraries
target_link_libraries(voix PRIVATE ${PAM_LIBRARIES})
if(LUA_FOUND)
    target_link_libraries(voix PRIVATE ${LUA_LIBRARIES})
else()
    message(WARNING "Lua not found - Lua config functionality will be disabled")
endif()

# Security hardening flags (compatible with both GCC and Clang)
target_compile_options(voix PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -fPIE
)

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    # Clang/LLVM specific flags
    target_compile_options(voix PRIVATE
        -fcolor-diagnostics
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC specific flags
    target_compile_options(voix PRIVATE
        -fdiagnostics-color=always
    )
endif()

# Install rules
install(TARGETS voix DESTINATION bin)

# Install configuration files
install(FILES config/voix.conf DESTINATION etc)

# Install PAM configuration
install(FILES pam.d/voix DESTINATION etc/pam.d)

# Install documentation
install(FILES docs/voix.1 DESTINATION share/man/man1)

# Install license files
install(FILES LICENSE LICENSE-VCL1.0 DESTINATION share/licenses/voix)

# Setuid installation - apply setuid bit during install
install(SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetuidInstall.cmake)
