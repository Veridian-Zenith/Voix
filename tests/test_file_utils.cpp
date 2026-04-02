#include "file_utils.h"
#include <print>
#include <fstream>
#undef NDEBUG
#include <cassert>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>

void test_isSecurePath() {
    Voix::FileUtils file_utils;
    const char* test_dir = "/tmp/voix_test_dir";
    const char* test_file = "/tmp/voix_test_dir/test.conf";

    // Clean up previous test runs
    system("rm -rf /tmp/voix_test_dir");

    // Create a directory for testing
    mkdir(test_dir, 0755);
    chown(test_dir, 0, 0); // root:root

    // Create a dummy file
    std::ofstream outfile(test_file);
    outfile << "test" << std::endl;
    outfile.close();

    // --- TEST CASES ---

    // Case 1: Secure setup (root owned, not world/group writable)
    chown(test_file, 0, 0);
    chmod(test_file, 0644); // rw-r--r--
    chown(test_dir, 0, 0);
    chmod(test_dir, 0755); // rwxr-xr-x
    assert(file_utils.isSecurePath(test_file) && "Case 1: Secure setup failed");

    // Case 2: File not owned by root
    chown(test_file, 1000, 1000); // non-root user
    assert(!file_utils.isSecurePath(test_file) && "Case 2: File not owned by root failed");
    chown(test_file, 0, 0); // revert

    // Case 3: File is group-writable
    chmod(test_file, 0664); // rw-rw-r--
    assert(!file_utils.isSecurePath(test_file) && "Case 3: File group-writable failed");
    chmod(test_file, 0644); // revert

    // Case 4: File is world-writable
    chmod(test_file, 0666); // rw-rw-rw-
    assert(!file_utils.isSecurePath(test_file) && "Case 4: File world-writable failed");
    chmod(test_file, 0644); // revert

    // Case 5: Directory not owned by root
    chown(test_dir, 1000, 1000);
    assert(!file_utils.isSecurePath(test_file) && "Case 5: Directory not owned by root failed");
    chown(test_dir, 0, 0); // revert

    // Case 6: Directory is group-writable
    chmod(test_dir, 0775); // rwxrwxr-x
    assert(!file_utils.isSecurePath(test_file) && "Case 6: Directory group-writable failed");
    chmod(test_dir, 0755); // revert

    // Case 7: Directory is world-writable
    chmod(test_dir, 0777); // rwxrwxrwx
    assert(!file_utils.isSecurePath(test_file) && "Case 7: Directory world-writable failed");
    chmod(test_dir, 0755); // revert

    // Clean up
    system("rm -rf /tmp/voix_test_dir");

    std::println("test_isSecurePath passed!");
}
