# CONFIG_PROPOSAL.md

## Overview

This document proposes a modernization of the `voix` configuration format to improve maintainability, readability, and ease of parsing.

## Current Configuration (`config/voix.conf`)

The current configuration uses a custom, keyword-based DSL:

```txt
sanctuary /tmp
path /bin:/sbin:/usr/bin:/usr/sbin

ordain trust :wheel
ordain trust initiate mask root rite /usr/bin/systemctl restart nginx
shun exiled
```

While this approach is concise, it presents several challenges:

1. **Complexity**: Parsing requires a custom, stateful tokenizer in `src/config.cpp`, which is prone to bugs and difficult to extend.
2. **Brittle**: The syntax is highly positional and relies on specific keyword orders.
3. **No Schema**: There is no validation or schema support.

## Proposed Configuration (YAML)

We propose switching to YAML for the configuration file. YAML provides:

1. **Human Readability**: Clear, structured data.
2. **Standardization**: Widespread support for parsing, validation, and tooling.
3. **Declarative Syntax**: Rules are defined as objects, improving clarity.

### Proposed Structure

```yaml
# Global settings
globals:
  sanctuary: /tmp
  # Paths can be defined as a list for clarity
  path:
    - /bin
    - /sbin
    - /usr/bin
    - /usr/sbin

# Access control rules
rules:
  - action: permit # Corresponds to 'ordain'
    identity: :wheel
    trust: true

  - action: permit
    identity: initiate
    mask: root
    # The 'rite' and arguments are structured clearly
    command: /usr/bin/systemctl
    args:
      - restart
      - nginx

  - action: deny # Corresponds to 'shun'
    identity: exiled
```

## Benefits of the New Structure

- **Ease of Parsing**: We can utilize a mature YAML library, completely eliminating the custom parsing logic in `src/config.cpp`.
- **Maintainability**: Adding new rule types or options (e.g., time-based restrictions) becomes straightforward without modifying the parser logic.
- **Robustness**: YAML naturally handles quoting, escaping, and complex data types (lists, maps) which were manual efforts in the current parser.
- **Validation**: We can easily define a JSON Schema to validate the configuration file before loading it.
