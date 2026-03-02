# SetuidInstall.cmake - Handle setuid bit installation
# This script is executed during CMake install phase
# The actual install prefix is available as CMAKE_INSTALL_PREFIX during install

# Find the voix binary that was just installed
if(EXISTS "${CMAKE_INSTALL_PREFIX}/bin/voix")
  set(VOIX_INSTALL_BINARY "${CMAKE_INSTALL_PREFIX}/bin/voix")
elseif(NOT "${VOIX_INSTALL_BINARY}" STREQUAL "")
  # Use the passed variable if provided
  set(VOIX_INSTALL_BINARY "${VOIX_INSTALL_BINARY}")
else()
  message(WARNING "Could not locate voix binary for setuid installation")
  return()
endif()

message(STATUS "Setting setuid bit on ${VOIX_INSTALL_BINARY}")

# Try to chown to root (requires root privileges)
execute_process(
  COMMAND chown root:root "${VOIX_INSTALL_BINARY}"
  RESULT_VARIABLE CHOWN_RESULT
  ERROR_QUIET
)

# Always try to set setuid+execute permissions
execute_process(
  COMMAND chmod 4755 "${VOIX_INSTALL_BINARY}"
  RESULT_VARIABLE CHMOD_RESULT
  ERROR_QUIET
)

# Check if we're running as root
if(NOT CHOWN_RESULT EQUAL 0)
  message(WARNING "Could not change ownership to root. This is expected when not running as root.")
  message(WARNING "For security, voix should be owned by root and have setuid bit set.")
  message(WARNING "To fix permissions, run: sudo chown root:root '${VOIX_INSTALL_BINARY}' && sudo chmod 4755 '${VOIX_INSTALL_BINARY}'")
else()
  message(STATUS "Successfully set setuid bit on voix binary")
endif()

if(NOT CHMOD_RESULT EQUAL 0)
  message(WARNING "Could not set permissions. Install completed, but you may need to set permissions manually.")
endif()
