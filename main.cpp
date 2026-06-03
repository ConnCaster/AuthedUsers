#include <systemd/sd-login.h>

#include "json.hpp"

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <sys/types.h>

struct AuthedUserInfo {
    uid_t uid = 0;
    std::string username;
    std::set<std::string> sessions;
};

using AuthedUsersByUid = std::map<uid_t, AuthedUserInfo>;
using json = nlohmann::ordered_json;

struct SystemdStringArray {
    char** values = nullptr;

    SystemdStringArray() = default;

    SystemdStringArray(const SystemdStringArray&) = delete;
    SystemdStringArray& operator=(const SystemdStringArray&) = delete;

    ~SystemdStringArray() {
        if (values == nullptr) {
            return;
        }

        for (char** it = values; *it != nullptr; ++it) {
            std::free(*it);
        }

        std::free(values);
    }
};

std::string SystemdErrorToString(int ret) {
    if (ret >= 0) {
        return {};
    }

    const int err = -ret;
    return std::string{std::strerror(err)} + " (" + std::to_string(ret) + ")";
}

std::string GetSessionUsernameOrUnknown(const char* session_id) {
    char* username_raw = nullptr;

    const int ret = sd_session_get_username(session_id, &username_raw);
    if (ret >= 0 && username_raw != nullptr) {
        std::string username{username_raw};
        std::free(username_raw);
        return username;
    }

    if (username_raw != nullptr) {
        std::free(username_raw);
    }

    return "unknown";
}

std::optional<AuthedUsersByUid> CollectAuthedUsersFromSystem() {
    SystemdStringArray sessions;

    const int sessions_count = sd_get_sessions(&sessions.values);
    if (sessions_count < 0) {
        std::cerr << "error: sd_get_sessions failed: "
                  << SystemdErrorToString(sessions_count) << '\n';
        return std::nullopt;
    }

    AuthedUsersByUid users;

    for (char** it = sessions.values; it != nullptr && *it != nullptr; ++it) {
        const char* session_id = *it;

        uid_t uid = 0;
        const int uid_ret = sd_session_get_uid(session_id, &uid);
        if (uid_ret < 0) {
            std::cerr << "warning: sd_session_get_uid failed for session '"
                      << session_id << "': "
                      << SystemdErrorToString(uid_ret) << '\n';
            continue;
        }

        auto& user_info = users[uid];
        user_info.uid = uid;

        if (user_info.username.empty() || user_info.username == "unknown") {
            user_info.username = GetSessionUsernameOrUnknown(session_id);
        }

        user_info.sessions.insert(session_id);
    }

    return users;
}

json ToJson(const AuthedUsersByUid& users) {
    json records = json::array();

    for (const auto& [uid, user_info] : users) {
        json sessions = json::array();

        for (const auto& session_id : user_info.sessions) {
            sessions.push_back(session_id);
        }

        json record;
        record["uid"] = static_cast<std::uint64_t>(uid);
        record["username"] = user_info.username;
        record["sessions"] = std::move(sessions);

        records.push_back(std::move(record));
    }

    return records;
}

int WriteCurrentAuthedUsersInfo(const std::filesystem::path& output_path) {
    const auto users = CollectAuthedUsersFromSystem();
    if (!users.has_value()) {
        return 1;
    }

    std::ofstream output(output_path, std::ios::out | std::ios::trunc);
    if (!output.is_open()) {
        std::cerr << "error: failed to open output file: "
                  << output_path.string() << '\n';
        return 1;
    }

    output << ToJson(users.value()).dump(4) << '\n';

    if (!output.good()) {
        std::cerr << "error: failed to write output file: "
                  << output_path.string() << '\n';
        return 1;
    }

    return 0;
}

int main() {
    const std::filesystem::path output_path{"authed_users.json"};
    return WriteCurrentAuthedUsersInfo(output_path);
}