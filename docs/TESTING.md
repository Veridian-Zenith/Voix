# Testing

Voix features automated test execution directly integrated into the build process.

## How it Works

When `BUILD_TESTING` is enabled (default for Debug builds):

- A modular test harness under `tests/` is compiled into a standalone
  `test_runner` binary registered with CTest.
- The same harness is linked into the `voix` binary itself, enabling
  `voix --run-tests`.
- The `voix` target depends on running the suite: **a failing test fails the
  build**, preventing broken binaries from being accidentally compiled or packaged.

> [!NOTE]
> In Release builds (`BUILD_TESTING=OFF`, the default) the entire harness —
> and the `--run-tests` code path — is compiled out of the shipped binary.
> `voix --run-tests` on a Release artifact reports *"Tests are not enabled in
> this build."* by design.

## Configuration

- To enable tests explicitly: `-DBUILD_TESTING=ON`
- To disable tests: `-DBUILD_TESTING=OFF`

### Building and Running Tests (Debug Mode)

```bash
cmake -B build-debug -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug && cmake --build build-debug
```

### Force-enabling Tests (Release Mode)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -G Ninja
cmake --build build
```

## Running the Suite Manually

```bash
# Via the standalone runner
./build-debug/test_runner

# Via CTest
ctest --test-dir build-debug --output-on-failure

# Via the voix binary itself (Debug/test builds only)
./build-debug/voix --run-tests
```

All three entry points execute the identical registered suite (84 tests).

<details>
<summary><b>Test module inventory</b></summary>

| Module file | Area covered |
| :--- | :--- |
| `test_permissions.cpp` | permit/deny, group rules, command-specific rules, first-match deny precedence, wildcard args, deny-aware `-l` listing |
| `test_config.cpp` | load success/failure, blocklist exact + `regex:` entries, malformed-regex rejection, envlist validation, rule options parsing, security-profile rule preservation, unconfined targets, schema validation |
| `test_security.cpp` | username validation, catastrophic rm/dd/mkfs/partition-tool detection incl. cwd-relative targets, blocklist integration, ticket-store roundtrip & tampering |
| `test_command.cpp` | security-profile resolution matrix (explicit / unconfined / restricted defaults) |
| `test_file_utils.cpp` | read/write, secure `O_NOFOLLOW` I/O roundtrips, symlink rejection, private-directory enforcement, command resolution incl. group-writable refusal |
| `test_logger.cpp` | timestamp format, control-character / log-forging sanitization |
| `test_system_utils.cpp` | UID/GID lookups, passwd lookups, environment application |
| `test_negative_security.cpp` | adversarial cases: encoded paths, symlink bypass, traversal args, config tampering, group spoofing, targetless-rule bypass, blocklist evasion, injection metacharacters, environment injection |

</details>

## Runtime Hardening Matrix

Beyond unit tests, the following flows are exercised against the locally
built setuid binary (see repository history for the transcript): trust/nopass
execution, `persist` ticket consume → refresh → `-k` invalidate lifecycle,
`nolog` audit suppression, `envlist` injection, restricted-tier
`PR_SET_NO_NEW_PRIVS` + PATH override + forced umask, exit-code propagation,
catastrophic-command blocks (`rm -rf /` variants, `dd` to raw devices),
blocklist `regex:` enforcement, pacman operation under the unconfined tier,
and config-tamper rejection (symlinks).