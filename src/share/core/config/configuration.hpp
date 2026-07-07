#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// 配置类：解析 TOML 格式配置文件，提供键值读取接口
// 支持 network.listen_endpoint、ipc.address、socks.backend 等所有运行时配置
// 不是完整 TOML 解析器，只支持扁平 key=value 和 [[sections]] 区块
namespace clink::core::config {

class Configuration {
public:
    Configuration() = default;

    static Configuration load_from_file(const std::filesystem::path& path);  // 从 toml 文件加载

    [[nodiscard]] const std::filesystem::path& source_path() const noexcept { return source_path_; } // 配置源文件路径
    [[nodiscard]] bool contains(std::string_view key) const;      // 键是否存在
    [[nodiscard]] std::string get_string(std::string_view key, std::string default_value = "") const;  // 读字符串
    [[nodiscard]] bool get_bool(std::string_view key, bool default_value = false) const;  // 读布尔值
    [[nodiscard]] int get_int(std::string_view key, int default_value = 0) const;         // 读整数
    [[nodiscard]] std::vector<std::string> get_list(std::string_view key) const;          // 读字符串列表
    [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }
    [[nodiscard]] std::vector<std::string> get_keys() const;

    void set(std::string key, std::string value);  // 写键值（用于热重载时自动加密 PSK 后回写）
    void save() const;                              // 持久化回文件

    static std::string trim(std::string_view text);        // 去除首尾空白
    static std::string strip_quotes(std::string_view text); // 去除首尾引号

private:
    using Table = std::unordered_map<std::string, std::string>;

    Table values_{};              // key → value 存储
    std::filesystem::path source_path_{};  // TOML 文件路径
};

}  // namespace clink::core::config
