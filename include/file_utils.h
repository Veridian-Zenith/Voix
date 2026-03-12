#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <string_view>
#include <optional>

namespace Voix {

using Path = std::string_view;
using Content = std::string_view;

class FileUtils {
public:
    FileUtils() = default;
    ~FileUtils() = default;

    bool fileExists(Path path) const;
    std::optional<std::string> readFile(Path path) const;
    bool writeFile(Path path, Content content) const;
};

} // namespace Voix

#endif // FILE_UTILS_H
