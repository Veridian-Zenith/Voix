cmake_minimum_required(VERSION 3.18)

# ---- Ignore External Flags ----
set(ENV{CFLAGS} "")
set(ENV{CXXFLAGS} "")
set(ENV{LDFLAGS} "")
set(CMAKE_C_FLAGS "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "" CACHE STRING "" FORCE)

project(Voix VERSION 2.7.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "Clang required. Found: ${CMAKE_CXX_COMPILER_ID}")
endif()

# ---- Compiler Flags ----
set(COMMON_FLAGS "-march=native -O3 -pipe -fno-plt -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fPIE -flto=thin -fvisibility=hidden -Wno-unused-variable -Wno-unused-parameter")
set(DEBUG_FLAGS "-g -fstandalone-debug -fno-omit-frame-pointer")

set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS} -fexperimental-library" CACHE STRING "" FORCE)

# ---- Linker Flags ----
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie -flto=thin")

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)
pkg_check_modules(LIBCAP REQUIRED libcap)

# ---- Target ----
file(GLOB_RECURSE VOIX_SOURCES src/*.cpp)
add_executable(voix ${VOIX_SOURCES})

target_include_directories(voix PRIVATE include ${PAM_INCLUDE_DIRS} ${LIBCAP_INCLUDE_DIRS})
target_link_libraries(voix PRIVATE ${PAM_LIBRARIES} ${LIBCAP_LIBRARIES})

if(BUILD_TESTING)
    target_sources(voix PRIVATE tests/test_main.cpp tests/test_security.cpp tests/test_file_utils.cpp)
endif()

# ---- Installation ----
include(GNUInstallDirs)

option(SET_PERMISSIONS "Set permissions and capabilities during install" ON)

if(SET_PERMISSIONS)
    install(TARGETS voix DESTINATION ${CMAKE_INSTALL_BINDIR}
            PERMISSIONS SETUID OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
else()
    install(TARGETS voix DESTINATION ${CMAKE_INSTALL_BINDIR}
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

install(FILES config/voix.conf DESTINATION /etc RENAME voix.conf PERMISSIONS OWNER_READ OWNER_WRITE)
install(FILES pam.d/voix DESTINATION /etc/pam.d PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
install(FILES docs/voix.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

target_compile_options(voix PRIVATE -Wall -Wextra)
target_link_options(voix PRIVATE)
