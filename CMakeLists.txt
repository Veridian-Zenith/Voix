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

project(Voix VERSION 4.1.2 LANGUAGES CXX)

# ---- Cache Acceleration ----
# Explicitly use ccache as the compiler launcher for speed and consistency
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "ccache found: ${CCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
else()
    message(WARNING "ccache not found. Proceeding with raw compilation.")
endif()

# ---- Project Standards ----
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Architecture Selection ----
# Allow overriding the architecture for generic binary builds (e.g., CI/CD)
set(VOIX_ARCH "native" CACHE STRING "Target architecture for compilation (default: native)")
message(STATUS "Targeting architecture: ${VOIX_ARCH}")

# ---- Toolchain Validation ----
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Clang required. Found: ${CMAKE_CXX_COMPILER_ID}")
endif()

# ---- Compiler & Feature Flags ----
# Optimized for the chosen architecture and C++26 experimental features
# Using LLVM toolchain (Clang + LLD + Oz optimization)
set(COMMON_FLAGS "-march=${VOIX_ARCH} -Oz -pipe -fno-plt -fstack-protector-strong \
-fstack-clash-protection -D_FORTIFY_SOURCE=3 -fPIE -flto=thin -fvisibility=hidden \
-fsanitize=cfi -fsanitize=shadow-call-stack \
-Wno-unused-variable -Wno-unused-parameter -Wno-unused-function -fexperimental-library -std=c++26")

set(DEBUG_FLAGS "-g -fstandalone-debug -fno-omit-frame-pointer")

set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}" CACHE STRING "" FORCE)

# ---- Linker Flags ----
# Utilizing LLD, ThinLTO caching, and Identical Code Folding (ICF)
set(CMAKE_EXE_LINKER_FLAGS "-fuse-ld=lld -Wl,-O3 -Wl,--as-needed -Wl,-z,relro -Wl,-z,now \
-Wl,-z,noexecstack -Wl,--icf=all \
-pie -flto=thin" CACHE STRING "" FORCE)

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)
pkg_check_modules(LIBCAP REQUIRED libcap)
pkg_check_modules(LIBSECCOMP REQUIRED libseccomp)
find_package(yaml-cpp REQUIRED)

# ---- Source & Executable ----
file(GLOB_RECURSE VOIX_SOURCES src/*.cpp)
list(REMOVE_ITEM VOIX_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
add_library(voix_lib STATIC ${VOIX_SOURCES})
add_executable(voix src/main.cpp)

target_link_libraries(voix_lib PUBLIC
    ${PAM_LIBRARIES}
    ${LIBCAP_LIBRARIES}
    ${LIBSECCOMP_LIBRARIES}
    yaml-cpp::yaml-cpp
)

target_include_directories(voix_lib PUBLIC
    include
    ${PAM_INCLUDE_DIRS}
    ${LIBCAP_INCLUDE_DIRS}
    ${LIBSECCOMP_INCLUDE_DIRS}
)

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
endif()

# ---- Installation ----
include(GNUInstallDirs)

option(ENABLE_PERMISSIONS "Set permissions and capabilities during install" ON)

if(ENABLE_PERMISSIONS)
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

