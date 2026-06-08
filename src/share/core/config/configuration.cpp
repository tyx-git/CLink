#include "src/share/core/config/configuration.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>

namespace clink::core::config {
namespace {

std::string normalize_key(std::string_view section, std::string_view key) {
    if (section.empty()) {
        return std::string{key};
    }
    std::string normalized;
    normalized.reserve(section.size() + 1 + key.size());
    normalized.append(section);
    normalized.push_back('.');
    normalized.append(key);
    return normalized;
}

bool is_list(std::string_view value) {
    return !value.empty() && value.front() == '[' && value.back() == ']';
}

std::vector<std::string> parse_list(std::string_view list_raw) {
    std::vector<std::string> items;
    if (!is_list(list_raw)) {
        return items;
    }

    std::string buffer;
    bool inside_string = false;
    for (size_t i = 1; i + 1 < list_raw.size(); ++i) {
        char ch = static_cast<char>(list_raw[i]);
        if (ch == '"') {
            inside_string = !inside_string;
            continue;
        }
        if (!inside_string && (ch == ',')) {
            auto trimmed = Configuration::trim(buffer);
            if (!trimmed.empty()) {
                items.emplace_back(Configuration::strip_quotes(trimmed));
            }
            buffer.clear();
            continue;
        }
        buffer.push_back(ch);
    }

    auto trimmed = Configuration::trim(buffer);
    if (!trimmed.empty()) {
        items.emplace_back(Configuration::strip_quotes(trimmed));
    }

    return items;
}

std::string strip_inline_comment(std::string_view text) {
    bool inside_string = false;
    char quote_char = '\0';
    bool escaped = false;

    for (size_t i = 0; i < text.size(); ++i) {
        const char ch = static_cast<char>(text[i]);
        if (escaped) {
            escaped = false;
            continue;
        }
        if (inside_string && ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"' || ch == '\'') {
            if (!inside_string) {
                inside_string = true;
                quote_char = ch;
            } else if (quote_char == ch) {
                inside_string = false;
                quote_char = '\0';
            }
            continue;
        }
        if (!inside_string && ch == '#') {
            return Configuration::trim(text.substr(0, i));
        }
    }

    return Configuration::trim(text);
}

std::string next_section_name(std::string_view section_header, std::map<std::string, int>& section_indices) {
    const bool is_array = section_header.size() > 4 && section_header[1] == '[' && section_header[section_header.size() - 2] == ']';
    if (is_array) {
        std::string section_name = Configuration::trim(section_header.substr(2, section_header.size() - 4));
        const int index = section_indices[section_name]++;
        return section_name + "[" + std::to_string(index) + "]";
    }

    return Configuration::trim(section_header.substr(1, section_header.size() - 2));
}

}  // namespace

Configuration Configuration::load_from_file(const std::filesystem::path& path) {
    std::ifstream input{path};
    if (!input) {
        throw std::runtime_error("Cannot open configuration file: " + path.string());
    }

    Configuration config;
    config.source_path_ = path;

    std::string current_section;
    std::map<std::string, int> section_indices;
    std::string line;
    while (std::getline(input, line)) {
        auto trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#') {
            continue;
        }

        if (trimmed.front() == '[' && trimmed.back() == ']') {
            current_section = next_section_name(trimmed, section_indices);
            continue;
        }

        auto delimiter = trimmed.find('=');
        if (delimiter == std::string::npos) {
            continue;
        }

        auto key = trim(std::string_view{trimmed}.substr(0, delimiter));
        auto value = strip_inline_comment(std::string_view{trimmed}.substr(delimiter + 1));
        if (key.empty()) {
            continue;
        }

        config.values_[normalize_key(current_section, key)] = std::string{value};
    }

    return config;
}

bool Configuration::contains(std::string_view key) const {
    return values_.find(std::string{key}) != values_.end();
}

std::string Configuration::get_string(std::string_view key, std::string default_value) const {
    auto it = values_.find(std::string{key});
    if (it == values_.end()) {
        return default_value;
    }
    return strip_quotes(it->second);
}

bool Configuration::get_bool(std::string_view key, bool default_value) const {
    auto raw = get_string(key, default_value ? "true" : "false");
    std::string lowered = raw;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "true" || lowered == "1") {
        return true;
    }
    if (lowered == "false" || lowered == "0") {
        return false;
    }
    return default_value;
}

int Configuration::get_int(std::string_view key, int default_value) const {
    auto it = values_.find(std::string{key});
    if (it == values_.end()) {
        return default_value;
    }

    int value = default_value;
    auto view = std::string_view{it->second};
    view = trim(view);
    auto result = std::from_chars(view.data(), view.data() + view.size(), value);
    if (result.ec == std::errc{}) {
        return value;
    }
    return default_value;
}

std::vector<std::string> Configuration::get_list(std::string_view key) const {
    auto it = values_.find(std::string{key});
    if (it == values_.end()) {
        return {};
    }
    auto view = trim(it->second);
    return parse_list(view);
}

std::vector<std::string> Configuration::get_keys() const {
    std::vector<std::string> keys;
    keys.reserve(values_.size());
    for (const auto& [key, _] : values_) {
        keys.push_back(key);
    }
    return keys;
}

void Configuration::set(std::string key, std::string value) {
    values_[std::move(key)] = std::move(value);
}

void Configuration::save() const {
    if (source_path_.empty()) return;

    std::ifstream input{source_path_};
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    input.close();

    std::ofstream output{source_path_};
    std::string current_section;
    std::map<std::string, int> section_indices;

    for (auto& l : lines) {
        auto trimmed = trim(l);
        if (trimmed.empty() || trimmed.front() == '#') {
            output << l << "\n";
            continue;
        }

        if (trimmed.front() == '[' && trimmed.back() == ']') {
            current_section = next_section_name(trimmed, section_indices);
            output << l << "\n";
            continue;
        }

        auto delimiter = trimmed.find('=');
        if (delimiter == std::string::npos) {
            output << l << "\n";
            continue;
        }

        auto key = trim(std::string_view{trimmed}.substr(0, delimiter));
        if (key.empty()) {
            output << l << "\n";
            continue;
        }

        std::string full_key = normalize_key(current_section, key);
        auto it = values_.find(full_key);
        if (it != values_.end()) {
            std::string val = it->second;
            if (!val.empty() && (val.find(' ') != std::string::npos || val.find('[') != std::string::npos)) {
                if (val.front() != '"' && val.front() != '[') {
                    val = '"' + val + '"';
                }
            }
            output << key << " = " << val << "\n";
        } else {
            output << l << "\n";
        }
    }
}

std::string Configuration::trim(std::string_view text) {
    auto begin = text.find_first_not_of(" \t\n\r");
    if (begin == std::string_view::npos) {
        return {};
    }
    auto end = text.find_last_not_of(" \t\n\r");
    return std::string{text.substr(begin, end - begin + 1)};
}

std::string Configuration::strip_quotes(std::string_view text) {
    if (text.size() >= 2) {
        auto first = text.front();
        auto last = text.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return std::string{text.substr(1, text.size() - 2)};
        }
    }
    return std::string{text};
}

}  // namespace clink::core::config
