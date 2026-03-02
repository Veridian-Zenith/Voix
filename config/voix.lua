-- Voix Lua Configuration
-- Simple access control rules for privilege escalation

-- Define access rules
rules = {
    -- Root always allowed without password
    {
        user = "root",
        nopass = true,
        actions = {"*"}
    },

    -- Wheel group members allowed with password
    {
        group = "wheel",
        nopass = false,
        actions = {"*"}
    },

    -- Sudo group members allowed with password
    {
        group = "sudo",
        nopass = false,
        actions = {"*"}
    },

    -- Add custom rules below:
    -- Example: Allow user 'admin' to run systemctl without password
    -- {
    --     user = "admin",
    --     nopass = true,
    --     actions = {"systemctl"}
    -- },
}

-- Return rules table
return rules
