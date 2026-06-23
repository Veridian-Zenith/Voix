cmake_minimum_required(VERSION 3.18)

# ---- Ignore External Flags ----
# Ensuring build consistency by ignoring environment-inherited flags
set(ENV{CFLAGS} "")
set(ENV{CXXFLAGS} "")
set(ENV{LDFLAGS} "")
set(CMAKE_C_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_DEBUG "" CACHE STRING "" FORCE)

project(Voix VERSION 4.5.0 LANGUAGES CXX)

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
option(VOIX_USE_MOLD "Use MOLD linker instead of LLD" ON)
option(VOIX_ENABLE_PAM "Enable PAM support" ON)
option(VOIX_ENABLE_CAP "Enable Capability support" ON)
option(VOIX_ENABLE_SECCOMP "Enable Seccomp support" ON)

# ---- Architecture Selection ----
# Allow overriding the architecture for generic binary builds (e.g., CI/CD)
set(VOIX_ARCH "native" CACHE STRING "Target architecture for compilation (default: native)")
message(STATUS "Targeting architecture: ${VOIX_ARCH}")
message(STATUS "Build options: MOLD=${VOIX_USE_MOLD}, PAM=${VOIX_ENABLE_PAM}, CAP=${VOIX_ENABLE_CAP}, SECCOMP=${VOIX_ENABLE_SECCOMP}")

# ---- Toolchain Validation ----
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Clang required. Found: ${CMAKE_CXX_COMPILER_ID}")
endif()

# ---- Compiler & Feature Flags ----
# Optimized for the chosen architecture and C++26 experimental features
# Using LLVM toolchain (Clang + LLD/MOLD + Oz optimization)
set(COMMON_FLAGS "-march=${VOIX_ARCH} -Oz -pipe -fno-plt -fstack-protector-strong \
-fstack-clash-protection -D_FORTIFY_SOURCE=3 -fPIE -flto=thin -fvisibility=hidden \
-fexperimental-library -std=c++26")

set(DEBUG_FLAGS "-g -fstandalone-debug -fno-omit-frame-pointer")
set(RELEASE_FLAGS "-O3 -DNDEBUG")

set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}" CACHE STRING "" FORCE)
string(APPEND CMAKE_CXX_FLAGS_DEBUG " ${COMMON_FLAGS} ${DEBUG_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS_RELEASE " ${COMMON_FLAGS} ${RELEASE_FLAGS}")

# ---- Linker Flags ----
# Utilizing LLD/MOLD, ThinLTO caching, and Identical Code Folding (ICF)
set(LINKER_FLAGS "-Wl,-O3 -Wl,--as-needed -Wl,-z,relro -Wl,-z,now \
-Wl,-z,noexecstack -Wl,--icf=all \
-pie -flto=thin")

if(VOIX_USE_MOLD)
    set(LINKER_FLAGS "-fuse-ld=mold ${LINKER_FLAGS}")
else()
    set(LINKER_FLAGS "-fuse-ld=lld ${LINKER_FLAGS}")
endif()

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

target_link_libraries(voix_lib PUBLIC yaml-cpp::yaml-cpp)
target_include_directories(voix_lib PUBLIC include)

if(VOIX_ENABLE_PAM)
    pkg_check_modules(PAM REQUIRED pam)
    target_link_libraries(voix_lib PUBLIC ${PAM_LIBRARIES})
    target_include_directories(voix_lib PUBLIC ${PAM_INCLUDE_DIRS})
    target_compile_definitions(voix_lib PUBLIC VOIX_WITH_PAM)
endif()

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
    add_dependencies(voix run_tests)
endif()

# ---- Installation ----
include(GNUInstallDirs)

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

install(FILES config/voix.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
        RENAME voix.conf
        PERMISSIONS OWNER_READ OWNER_WRITE)

install(FILES pam.d/voix DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pam.d
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES docs/voix.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

