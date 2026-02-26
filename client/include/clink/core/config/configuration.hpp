#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clink::core::config {

class Configuration {
public:
    Configuration() = default;

    static Configuration load_from_file(const std::filesystem::path& path);

    [[nodiscard]] const std::filesystem::path& source_path() const noexcept { return source_path_; }
    [[nodiscard]] bool contains(std::string_view key) const;
    [[nodiscard]] std::string get_string(std::string_view key, std::string default_value = "") const;
    [[nodiscard]] bool get_bool(std::string_view key, bool default_value = false) const;
    [[nodiscard]] int get_int(std::string_view key, int default_value = 0) const;
    [[nodiscard]] std::vector<std::string> get_list(std::string_view key) const;
    [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }
    [[nodiscard]] std::vector<std::string> get_keys() const;

    void set(std::string key, std::string value);

    static std::string trim(std::string_view text);
    static std::string strip_quotes(std::string_view text);

private:
    using Table = std::unordered_map<std::string, std::string>;

    Table values_{};
    std::filesystem::path source_path_{};
};

}  // namespace clink::core::config
