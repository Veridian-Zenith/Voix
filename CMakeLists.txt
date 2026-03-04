cmake_minimum_required(VERSION 3.18)
project(Voix VERSION 2.2.0 LANGUAGES CXX)

# ---- Standards ----
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

# ---- Options ----
option(VOIX_SETUID_INSTALL "Install voix with setuid bit" ON)

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)

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
)

target_link_libraries(voix PRIVATE ${PAM_LIBRARIES})

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
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(voix PRIVATE -fdiagnostics-color=always)
endif()

# ---- Linker Hardening ----
target_link_options(voix PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -pie
)

# ---- Install Targets ----
install(TARGETS voix
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# ---- Deterministic Setuid Handling ----
if(VOIX_SETUID_INSTALL)
    install(CODE "
        message(STATUS \"Setting setuid bit on voix binary\")
        execute_process(
            COMMAND chown root:root \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/voix\"
            RESULT_VARIABLE CHOWN_RESULT
        )
        execute_process(
            COMMAND chmod 4755 \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/voix\"
            RESULT_VARIABLE CHMOD_RESULT
        )

        if(NOT CHOWN_RESULT EQUAL 0 OR NOT CHMOD_RESULT EQUAL 0)
            message(FATAL_ERROR \"Failed to apply setuid permissions. Install must be run as root.\")
        endif()
    ")
endif()

# ---- Config Files ----
install(FILES config/voix.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
)

install(FILES pam.d/voix
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pam.d
)

install(FILES docs/voix.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

install(FILES LICENSE
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/voix
)
