#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <set>
#include "server/include/clink/core/config/configuration.hpp"

namespace clink::core::policy {

struct Policy {
    std::optional<uint64_t> max_bandwidth_up;   // bps
    std::optional<uint64_t> max_bandwidth_down; // bps
    std::optional<uint32_t> session_timeout;    // seconds
    std::optional<std::vector<std::string>> allowed_subnets;
    std::optional<bool> allow_split_tunneling;

    void merge(const Policy& other) {
        if (other.max_bandwidth_up) max_bandwidth_up = other.max_bandwidth_up;
        if (other.max_bandwidth_down) max_bandwidth_down = other.max_bandwidth_down;
        if (other.session_timeout) session_timeout = other.session_timeout;
        if (other.allowed_subnets) allowed_subnets = other.allowed_subnets;
        if (other.allow_split_tunneling) allow_split_tunneling = other.allow_split_tunneling;
    }
};

class PolicyEngine {
public:
    PolicyEngine() {
        // Default global policy
        global_policy_.max_bandwidth_up = 100 * 1024 * 1024; // 100 Mbps
        global_policy_.max_bandwidth_down = 100 * 1024 * 1024;
        global_policy_.session_timeout = 3600;
        global_policy_.allow_split_tunneling = true;
        global_policy_.allowed_subnets = std::vector<std::string>{"0.0.0.0/0"};
    }

    void load_from_config(const clink::core::config::Configuration& config) {
        // Load global policy
        load_policy(config, "policy.global", global_policy_);

        // Load group policies
        auto keys = config.get_keys();
        std::set<std::string> groups;
        std::set<std::string> devices;

        for (const auto& key : keys) {
            if (key.rfind("policy.groups.", 0) == 0) {
                auto sub = key.substr(14); // length of "policy.groups."
                auto dot = sub.find('.');
                if (dot != std::string::npos) {
                    groups.insert(sub.substr(0, dot));
                }
            } else if (key.rfind("policy.devices.", 0) == 0) {
                auto sub = key.substr(15); // length of "policy.devices."
                auto dot = sub.find('.');
                if (dot != std::string::npos) {
                    devices.insert(sub.substr(0, dot));
                }
            }
        }

        for (const auto& group : groups) {
            Policy p;
            load_policy(config, "policy.groups." + group, p);
            group_policies_[group] = p;
        }

        for (const auto& device : devices) {
            Policy p;
            load_policy(config, "policy.devices." + device, p);
            device_policies_[device] = p;
        }
    }

    void set_group_policy(const std::string& group_id, const Policy& policy) {
        group_policies_[group_id] = policy;
    }

    void set_device_policy(const std::string& device_id, const Policy& policy) {
        device_policies_[device_id] = policy;
    }

    Policy evaluate(const std::string& device_id, const std::string& group_id = "") {
        Policy effective = global_policy_;

        if (!group_id.empty()) {
            auto it = group_policies_.find(group_id);
            if (it != group_policies_.end()) {
                effective.merge(it->second);
            }
        }

        auto it = device_policies_.find(device_id);
        if (it != device_policies_.end()) {
            effective.merge(it->second);
        }

        return effective;
    }

private:
    void load_policy(const clink::core::config::Configuration& config, const std::string& prefix, Policy& policy) {
        if (config.contains(prefix + ".max_bandwidth_up")) {
            policy.max_bandwidth_up = static_cast<uint64_t>(config.get_int(prefix + ".max_bandwidth_up"));
        }
        if (config.contains(prefix + ".max_bandwidth_down")) {
            policy.max_bandwidth_down = static_cast<uint64_t>(config.get_int(prefix + ".max_bandwidth_down"));
        }
        if (config.contains(prefix + ".session_timeout")) {
            policy.session_timeout = static_cast<uint32_t>(config.get_int(prefix + ".session_timeout"));
        }
        if (config.contains(prefix + ".allow_split_tunneling")) {
            policy.allow_split_tunneling = config.get_bool(prefix + ".allow_split_tunneling");
        }
        if (config.contains(prefix + ".allowed_subnets")) {
            policy.allowed_subnets = config.get_list(prefix + ".allowed_subnets");
        }
    }

    Policy global_policy_;
    std::unordered_map<std::string, Policy> group_policies_;
    std::unordered_map<std::string, Policy> device_policies_;
};

} // namespace clink::core::policy
