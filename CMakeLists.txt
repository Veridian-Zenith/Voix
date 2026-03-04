cmake_minimum_required(VERSION 3.18)
project(Voix VERSION 2.2.0 LANGUAGES CXX)

# ---- Standards ----
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

# ---- Install Binary ----
install(TARGETS voix
    RUNTIME DESTINATION /usr/bin
)

# ---- Setuid Handling ----
if(VOIX_SETUID_INSTALL)
    install(CODE "
        set(VOIX_BINARY \"\$ENV{DESTDIR}/usr/bin/voix\")
        if(EXISTS \${VOIX_BINARY})
            message(STATUS \"Setting setuid bit on \${VOIX_BINARY}...\")
            execute_process(COMMAND chown root:root \${VOIX_BINARY} RESULT_VARIABLE CHOWN_RESULT ERROR_QUIET)
            execute_process(COMMAND chmod 4755 \${VOIX_BINARY} RESULT_VARIABLE CHMOD_RESULT ERROR_QUIET)

            if(NOT CHOWN_RESULT EQUAL 0 OR NOT CHMOD_RESULT EQUAL 0)
                message(WARNING \"Could not fully set setuid on voix. Make sure to run install as root.\")
            else()
                message(STATUS \"Setuid successfully applied to voix binary.\")
            endif()
        else()
            message(WARNING \"Voix binary not found at \${VOIX_BINARY}, cannot set setuid.\")
        endif()
    ")
endif()

# ---- Config Files ----
install(FILES config/voix.conf
    DESTINATION /etc
)

install(FILES pam.d/voix
    DESTINATION /etc/pam.d
)

# ---- Manpage ----
install(FILES docs/voix.1
    DESTINATION /usr/share/man/man1
)

# ---- License ----
install(FILES LICENSE
    DESTINATION /usr/share/licenses/voix
)
