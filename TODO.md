# Voix Development TODO

## Authentication & Authorization
- [x] Fix authentication logic in Voix class to use configuration-based permissions instead of sudo privileges
- [x] Implement proper PAM authentication integration
- [x] Fix the isAllowed() method to properly check config-based permissions

## Compilation & Build
- [x] Fix compilation issues and rebuild the project
- [x] Ensure LLVM/clang/thinlto integration works correctly
- [x] Verify TCMALLOC integration

## Configuration Parsing
- [x] Fix configuration parsing logic to properly handle user-specific command permissions
- [x] Implement secure-by-default command validation (no commands allowed unless explicitly configured)

## Testing
- [x] Test the fixed authentication system
- [x] Add example configurations for command restrictions per user/group
- [ ] Add comprehensive testing suite
- [ ] Verify security hardening and performance optimizations

## Racket Implementation
- [ ] Create Racket alternative implementation
- [ ] Ensure feature parity with C++ version

## Documentation
- [ ] Update documentation and usage examples
- [ ] Improve security documentation
- [ ] Add configuration examples

## Security & Performance
- [ ] Audit security hardening flags
- [ ] Optimize memory usage with TCMALLOC
- [ ] Ensure minimal dependencies

## Deployment
- [ ] Create installation scripts
- [ ] Add systemd integration
- [ ] Create package configuration
