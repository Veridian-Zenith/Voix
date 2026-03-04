#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <optional>

namespace Voix {

using Path = std::string;
using Content = std::string;

class FileUtils {
public:
    FileUtils() = default;
    ~FileUtils() = default;

    bool fileExists(const Path& path) const;
    std::optional<std::string> readFile(const Path& path) const;
    bool writeFile(const Path& path, const Content& content) const;
};

} // namespace Voix

#endif // FILE_UTILS_H
