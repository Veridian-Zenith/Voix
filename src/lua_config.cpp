/**
 * @file lua_config.cpp
 * @brief Basic Lua configuration implementation (stub)
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "lua_config.h"
#include <vector>
#include <fstream>
#include <sstream>

namespace Voix {

LuaConfig::LuaConfig() {}

LuaConfig::~LuaConfig() {}

bool LuaConfig::loadConfig(const std::string& config_path) {
    // Try to load as Lua config first
    std::ifstream file(config_path);
    if (!file.is_open()) {
        return false;
    }

    // For now, just check if file exists and is readable
    // In a full implementation, this would parse Lua config
    return true;
}

std::vector<Rule> LuaConfig::getRules() const {
    // Default rule: allow root to do anything
    std::vector<Rule> rules;

    Rule root_rule;
    root_rule.ident = "root";
    root_rule.action = Rule::PERMIT;
    root_rule.options = Rule::NOPASS;
    rules.push_back(root_rule);

    // Allow wheel group to do anything
    Rule wheel_rule;
    wheel_rule.ident = ":wheel";
    wheel_rule.action = Rule::PERMIT;
    wheel_rule.options = Rule::NOPASS;
    rules.push_back(wheel_rule);

    return rules;
}

bool LuaConfig::isUserAllowed(const std::string& username) const {
    // Check against our default rules
    auto rules = getRules();

    for (const auto& rule : rules) {
        if (rule.ident == username || rule.ident == ":wheel") {
            return rule.action == Rule::PERMIT;
        }
    }

    return false;
}

bool LuaConfig::validateCommand(const std::string& username,
                              const std::string& /*command*/,
                              const std::vector<std::string>& /*args*/) const {
    // For now, just check if user is allowed
    return isUserAllowed(username);
}

// Stub functions - would be implemented in full Lua version
void LuaConfig::registerLuaFunctions() {}
void LuaConfig::parseLuaRules() {}
void LuaConfig::parseLuaRule(lua_State* /*L*/, int /*index*/) {}
} // namespace Voix
