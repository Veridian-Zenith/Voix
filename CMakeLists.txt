cmake_minimum_required(VERSION 3.30)

# ---- Ignore External Flags ----
# Ensuring build consistency by ignoring environment-inherited flags
set(ENV{CFLAGS} "")
set(ENV{CXXFLAGS} "")
set(ENV{LDFLAGS} "")
set(CMAKE_C_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_DEBUG "" CACHE STRING "" FORCE)

project(Voix VERSION 4.11.0 LANGUAGES CXX)
# ---- Cache Acceleration ----
# Explicitly use ccache as the compiler launcher for speed and consistency
# (disabled during CodeQL analysis to allow proper build tracing)
if(NOT DEFINED ENV{CCACHE_DISABLE})
    find_program(CCACHE_PROGRAM ccache)
    if(CCACHE_PROGRAM)
        message(STATUS "ccache found: ${CCACHE_PROGRAM}")
        set(CMAKE_C_COMPILER_LAUNCHER   "${CCACHE_PROGRAM}")
        set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    else()
        message(WARNING "ccache not found. Proceeding with raw compilation.")
    endif()
else()
    message(STATUS "ccache disabled (likely CodeQL analysis)")
endif()

# ---- Project Standards ----
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Options ----
option(VOIX_ENABLE_CAP "Enable Capability support" ON)
option(VOIX_ENABLE_SECCOMP "Enable Seccomp support" ON)
option(VOIX_STATIC_YAML_CPP
       "Statically link yaml-cpp (portable release binaries without a versioned soname dependency)" OFF)

# ---- Architecture Selection ----
# Allow overriding the architecture for generic binary builds (e.g., CI/CD)
set(VOIX_ARCH "native" CACHE STRING "Target architecture for compilation (default: native)")
message(STATUS "Targeting architecture: ${VOIX_ARCH}")
message(STATUS "Build options: CAP=${VOIX_ENABLE_CAP}, SECCOMP=${VOIX_ENABLE_SECCOMP}")

# ---- Toolchain Validation ----
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Clang required. Found: ${CMAKE_CXX_COMPILER_ID}")
endif()

# ---- Compiler & Feature Flags ----
# Optimized for the chosen architecture and C++26 experimental features.
# LLVM-only toolchain (Clang + LLD). Hardening notes:
#   -fvisibility=hidden / -flto=thin : minimize exported surface, LTO
#   -fstack-protector-strong / -fstack-clash-protection : stack safety
#   -D_FORTIFY_SOURCE=3 : fortified libc functions
#   -ftrivial-auto-var-init=zero : deterministic stack (kills uninit-read UAF/info-leak)
#   -fcf-protection=full : CET indirect-branch + return landing-pad protection
#   -fexperimental-library : C++26 experimental features
set(COMMON_FLAGS "-march=${VOIX_ARCH} -pipe -fno-plt -fstack-protector-strong \
-fstack-clash-protection -D_FORTIFY_SOURCE=3 -fPIE -flto=thin -fvisibility=hidden \
-ftrivial-auto-var-init=zero -fcf-protection=full -ffunction-sections -fdata-sections -fstrict-flex-arrays=3 \
-fexperimental-library -std=c++26")

set(DEBUG_FLAGS "-Og -g -fstandalone-debug -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS")
set(RELEASE_FLAGS "-O2 -DNDEBUG")

set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}" CACHE STRING "" FORCE)
string(APPEND CMAKE_CXX_FLAGS_DEBUG " ${COMMON_FLAGS} ${DEBUG_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS_RELEASE " ${COMMON_FLAGS} ${RELEASE_FLAGS}")

# ---- Linker Flags ----
# LLVM LLD, ThinLTO, full RELRO. (CET/IBT+Shadow-Stack linker flags are
# omitted because some lld versions reject -z ibt/-z shstk; the compiler-side
# -fcf-protection=full still emits endbr landing pads for CET-capable targets.)
set(LINKER_FLAGS "-fuse-ld=lld -Wl,-O3 -Wl,--as-needed -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now \
-Wl,-z,noexecstack -Wl,-z,pack-relative-relocs \
-Wl,--icf=all \
-pie -flto=thin")

set(CMAKE_EXE_LINKER_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${LINKER_FLAGS}" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${LINKER_FLAGS} -Wl,--strip-all" CACHE STRING "" FORCE)

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
find_package(yaml-cpp REQUIRED)

# ---- Source & Executable ----
file(GLOB_RECURSE VOIX_SOURCES src/*.cpp)
list(REMOVE_ITEM VOIX_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
add_library(voix_lib STATIC ${VOIX_SOURCES})
add_executable(voix src/main.cpp)

if(VOIX_STATIC_YAML_CPP)
    # Link the static archive directly so the produced binary does not
    # reference any versioned yaml-cpp soname (libyaml-cpp.so.N) and therefore
    # runs on distributions shipping a different yaml-cpp ABI.
    find_library(YAML_CPP_STATIC_LIBRARY NAMES libyaml-cpp.a REQUIRED)
    message(STATUS "Linking yaml-cpp statically: ${YAML_CPP_STATIC_LIBRARY}")
    target_link_libraries(voix_lib PUBLIC ${YAML_CPP_STATIC_LIBRARY})
else()
    target_link_libraries(voix_lib PUBLIC yaml-cpp::yaml-cpp)
endif()
target_include_directories(voix_lib PUBLIC include)

# PAM is required — authentication is unconditional in the source code.
pkg_check_modules(PAM REQUIRED pam)
target_link_libraries(voix_lib PUBLIC ${PAM_LIBRARIES})
target_include_directories(voix_lib PUBLIC ${PAM_INCLUDE_DIRS})

if(VOIX_ENABLE_CAP)
    pkg_check_modules(LIBCAP REQUIRED libcap)
    target_link_libraries(voix_lib PUBLIC ${LIBCAP_LIBRARIES})
    target_include_directories(voix_lib PUBLIC ${LIBCAP_INCLUDE_DIRS})
    target_compile_definitions(voix_lib PUBLIC VOIX_WITH_CAP)
endif()

if(VOIX_ENABLE_SECCOMP)
    pkg_check_modules(LIBSECCOMP REQUIRED libseccomp)
    target_link_libraries(voix_lib PUBLIC ${LIBSECCOMP_LIBRARIES})
    target_include_directories(voix_lib PUBLIC ${LIBSECCOMP_INCLUDE_DIRS})
    target_compile_definitions(voix_lib PUBLIC VOIX_WITH_SECCOMP)
endif()

target_link_libraries(voix PRIVATE voix_lib)

# Single-source version string for printVersion()
target_compile_definitions(voix PRIVATE VOIX_VERSION="${PROJECT_VERSION}")

target_compile_options(voix_lib PRIVATE -Wall -Wextra)
target_compile_options(voix PRIVATE -Wall -Wextra)

# ---- Testing Logic ----
# Tests are managed by CTest and only built in Debug mode
if(NOT DEFINED BUILD_TESTING)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(BUILD_TESTING ON CACHE BOOL "Build tests" FORCE)
    else()
        set(BUILD_TESTING OFF CACHE BOOL "Build tests" FORCE)
    endif()
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
    # Wire the test harness into the main binary so `voix --run-tests` works
    # in test builds (Debug) while remaining fully absent from Release.
    target_include_directories(voix PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(voix PRIVATE BUILD_TESTING=1)
    target_link_libraries(voix PRIVATE voix_tests)
endif()

# ---- Installation ----
include(GNUInstallDirs)

# Force sysconfdir to /etc regardless of install prefix,
# as this is the standard location on all Linux distributions.
set(CMAKE_INSTALL_SYSCONFDIR "/etc" CACHE PATH "" FORCE)

option(ENABLE_PERMISSIONS "Set permissions and capabilities during install" ON)

if(ENABLE_PERMISSIONS)
    install(CODE [[
        execute_process(COMMAND id -u
            OUTPUT_VARIABLE _voix_uid
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(NOT _voix_uid EQUAL 0)
            message(FATAL_ERROR "ENABLE_PERMISSIONS=ON requires root privileges.\n"
                    "  Run: sudo cmake --install build\n"
                    "  Or reconfigure with: -DENABLE_PERMISSIONS=OFF")
        endif()
    ]])
    install(TARGETS voix RUNTIME DESTINATION bin
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID)
else()
    install(TARGETS voix RUNTIME DESTINATION bin
            PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

# Never overwrite an administrator's live configuration: if /etc/voix.conf
# already exists, the shipped sample lands as voix.conf.new instead.
install(CODE [[
    if(DEFINED ENV{DESTDIR})
        set(_voix_sysconf "$ENV{DESTDIR}/etc")
    else()
        set(_voix_sysconf "/etc")
    endif()
    get_filename_component(_voix_conf_src "${CMAKE_CURRENT_SOURCE_DIR}/config/voix.conf" ABSOLUTE)
    get_filename_component(_voix_pam_src "${CMAKE_CURRENT_SOURCE_DIR}/pam.d/voix" ABSOLUTE)
    file(MAKE_DIRECTORY "${_voix_sysconf}/pam.d")
    foreach(item IN ITEMS "voix.conf;${_voix_conf_src}" "pam.d/voix;${_voix_pam_src}")
        list(GET item 0 _rel)
        list(GET item 1 _src)
        if(EXISTS "${_voix_sysconf}/${_rel}")
            file(COPY_FILE "${_src}" "${_voix_sysconf}/${_rel}.new")
            message(STATUS "Existing ${_rel} preserved; new sample installed as ${_rel}.new")
        else()
            file(COPY_FILE "${_src}" "${_voix_sysconf}/${_rel}")
        endif()
    endforeach()
    file(CHMOD "${_voix_sysconf}/voix.conf" PERMISSIONS OWNER_READ OWNER_WRITE)
    file(CHMOD "${_voix_sysconf}/pam.d/voix" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    # Sanctuary directory used for persisted authentication timestamps
    # (see core.sanctuary in the configuration guide).
    file(MAKE_DIRECTORY "/var/lib/voix")
    file(CHMOD "/var/lib/voix" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
]])

install(FILES docs/voix.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

