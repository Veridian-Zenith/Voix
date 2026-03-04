cmake_minimum_required(VERSION 3.18)
project(Voix VERSION 2.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)

# Source files
set(VOIX_SOURCES
    src/main.cpp
    src/voix.cpp
    src/security.cpp
    src/config.cpp
    src/file_utils.cpp
    src/command.cpp
    src/logger.cpp
    src/system_utils.cpp
    src/pam_utils.cpp
    src/authenticator.cpp
    src/permission_checker.cpp
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${PAM_INCLUDE_DIRS})

# Create executable
add_executable(voix ${VOIX_SOURCES})

# Link libraries
target_link_libraries(voix PRIVATE ${PAM_LIBRARIES})


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
install(TARGETS voix DESTINATION /usr/bin)

# Install configuration files
install(FILES config/voix.conf DESTINATION /etc)

# Install PAM configuration
install(FILES pam.d/voix DESTINATION /etc/pam.d)

# Install documentation
install(FILES docs/voix.1 DESTINATION /usr/share/man/man1)

# Install license file
install(FILES LICENSE DESTINATION /usr/share/licenses/voix)

# Setuid installation - apply setuid bit and root ownership during install
install(SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetuidInstall.cmake)

