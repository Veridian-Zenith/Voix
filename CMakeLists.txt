cmake_minimum_required(VERSION 3.18)

# ---- Ignore External Flags ----
# We clear these BEFORE the project() call to ensure the initial compiler probe
# is isolated from user environment pollution.
set(ENV{CFLAGS} "")
set(ENV{CXXFLAGS} "")
set(ENV{LDFLAGS} "")
set(CMAKE_C_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "" CACHE STRING "" FORCE)

project(Voix VERSION 2.5.1 LANGUAGES CXX)

# ---- Standards ----
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "The Elders require the LLVM Clang toolchain to forge this project. Found: ${CMAKE_CXX_COMPILER_ID}")
endif()

# ---- Compiler Flags ----
# Common optimization and warnings
set(COMMON_FLAGS "-march=native -O3 -pipe -fno-plt \
-Wno-unused-variable -Wno-unused-parameter \
-Wno-unused-function -Wno-unused-but-set-variable \
-Wno-missing-field-initializers -Wno-sign-compare \
-Wno-unused-result")

# Debug / Sanitizers
set(DEBUG_FLAGS "-g -fstandalone-debug \
-fno-omit-frame-pointer \
-fno-optimize-sibling-calls")

# Combine flags for C and C++
set(ALL_C_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}")
set(ALL_CXX_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}")

# Apply flags explicitly
set(CMAKE_C_FLAGS "${ALL_C_FLAGS}" CACHE STRING "C compiler flags" FORCE)
set(CMAKE_CXX_FLAGS "${ALL_CXX_FLAGS} -fexperimental-library" CACHE STRING "C++ compiler flags" FORCE)

# ---- Linker Flags ----
set(LDFLAGS "-fuse-ld=lld -Wl,-O1,--as-needed,-z,relro,-z,now")
set(CMAKE_EXE_LINKER_FLAGS "${LDFLAGS}" CACHE STRING "Executable linker flags" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "${LDFLAGS}" CACHE STRING "Shared linker flags" FORCE)

# ---- Options ----
option(BUILD_TESTING "Build with testing enabled" ON)

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)
pkg_check_modules(LIBCAP REQUIRED libcap)

# ---- Sources ----
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

add_executable(voix ${VOIX_SOURCES})

target_include_directories(voix PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PAM_INCLUDE_DIRS}
    ${LIBCAP_INCLUDE_DIRS}
)

target_link_libraries(voix PRIVATE
    ${PAM_LIBRARIES}
    ${LIBCAP_LIBRARIES}
)

if(BUILD_TESTING)
    target_sources(voix PRIVATE
        tests/test_main.cpp
        tests/test_security.cpp
        tests/test_file_utils.cpp
    )
endif()



# ---- Installation ----
include(GNUInstallDirs)
# Install the Shadow Weave (Binary)
# Note: Ownership (root:root) should be handled by the package manager or installer
install(
    TARGETS voix
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

# Grant Arcane Powers (Capabilities) post-installation
install(CODE "
    execute_process(
        COMMAND setcap cap_audit_write,cap_dac_read_search+ep \"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/voix\"
        RESULT_VARIABLE res
    )
    if(NOT res EQUAL 0)
        message(FATAL_ERROR \"Failed to set capabilities on voix binary.\")
    endif()
")

# ---- Advanced Installation ----
# Install the Arcane Runes (Configuration)
# Note: Ownership (root:root) should be handled by the package manager or installer
install(
    FILES config/voix.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
    RENAME voix.conf
    PERMISSIONS
        OWNER_READ
        OWNER_WRITE
)

# Install the Ritual of Proof (PAM)
# Note: Ownership (root:root) should be handled by the package manager or installer
# Note: On some systems this might need to be /usr/lib/pam.d
install(
    FILES pam.d/voix
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pam.d
    PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

# Install the Chronicles (Man Page)
install(
    FILES docs/voix.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

# ---- Compiler Hardening ----
target_compile_options(voix PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -fPIE
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang")
    target_compile_options(voix PRIVATE -fcolor-diagnostics)
endif()

# ---- Linker Hardening ----
target_link_options(voix PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -pie
)


