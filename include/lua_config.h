/**
 * @file lua_config.h
 * @brief Lua configuration support for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef LUA_CONFIG_H
#define LUA_CONFIG_H

#include <string>
#include <vector>
#include <memory>
#include "voix.h"

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

namespace Voix {

class LuaConfig {
public:
    LuaConfig();
    ~LuaConfig();

    /**
     * @brief Load Lua configuration file
     * @param config_path Path to Lua configuration file
     * @return true if successful, false otherwise
     */
    bool loadConfig(const std::string& config_path);

    /**
     * @brief Get rules from Lua configuration
     * @return Vector of rules
     */
    std::vector<Rule> getRules() const;

    /**
     * @brief Check if user is allowed based on Lua configuration
     * @param username Username to check
     * @return true if allowed, false otherwise
     */
    bool isUserAllowed(const std::string& username) const;

    /**
     * @brief Validate command using Lua rules
     * @param username Username attempting command
     * @param command Command to validate
     * @param args Command arguments
     * @return true if valid, false otherwise
     */
    bool validateCommand(const std::string& username, const std::string& command,
                         const std::vector<std::string>& args) const;

private:
    std::vector<Rule> rules_;

    // Helper functions for Lua integration
    void registerLuaFunctions();
    void parseLuaRules();
    void parseLuaRule(lua_State* L, int index);
};

} // namespace Voix

#endif // LUA_CONFIG_H
