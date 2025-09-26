#include "include/password.hpp"
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <lua.hpp>

std::string get_password() {
  std::cout << "Password: ";
  termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::string password;
  std::getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << std::endl;
  return password;
}

void display_version() {
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    std::string version = "unknown";
    if (luaL_dofile(L, "version.lua") == LUA_OK) {
        if (lua_isstring(L, -1)) {
            version = lua_tostring(L, -1);
        }
    }
    lua_close(L);
    std::cout << "voix version " << version << std::endl;
}

void display_help() {
    std::cout << "voix: a modern, secure, and simple sudo replacement." << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  voix [options] <command> [args...]" << std::endl;
    std::cout << "  voix check [config-file]           # Validate configuration file" << std::endl;
    std::cout << "  voix validate [config-file]        # Validate and display configuration" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help     Show this help message and exit." << std::endl;
    std::cout << "  -v, --version  Show the version of voix and exit." << std::endl;
    std::cout << std::endl;
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Default config: /etc/voix.conf" << std::endl;
    std::cout << "  Set VOIX_CONFIG to override config path" << std::endl;
    std::cout << std::endl;
    std::cout << "For more information, see the README.md file." << std::endl;
}
