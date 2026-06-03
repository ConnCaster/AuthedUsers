#include <systemd/sd-login.h>

#include "json.hpp"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <pwd.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

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

std::optional<std::string> GetUsernameByUid(uid_t uid) {
    long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buffer_size <= 0) {
        buffer_size = 16 * 1024;
    }

    std::vector<char> buffer(static_cast<size_t>(buffer_size));

    passwd pwd{};
    passwd* result = nullptr;

    const int ret = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);
    if (ret != 0 || result == nullptr || pwd.pw_name == nullptr) {
        return std::nullopt;
    }

    return std::string{pwd.pw_name};
}

std::string GetSessionUsername(const char* session_id, uid_t uid) {
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

    const auto username_from_passwd = GetUsernameByUid(uid);
    if (username_from_passwd.has_value()) {
        return *username_from_passwd;
    }

    return "unknown";
}

AuthedUsersByUid CollectAuthedUsersFromSystem() {
    SystemdStringArray sessions;

    const int sessions_count = sd_get_sessions(&sessions.values);
    if (sessions_count < 0) {
        throw std::runtime_error{
            "sd_get_sessions failed: " + SystemdErrorToString(sessions_count)
        };
    }

    AuthedUsersByUid users;

    for (char** it = sessions.values; it != nullptr && *it != nullptr; ++it) {
        const char* session_id = *it;

        uid_t uid = 0;
        const int uid_ret = sd_session_get_uid(session_id, &uid);
        if (uid_ret < 0) {
            std::cerr << "warning: sd_session_get_uid failed for session '"
                      << session_id << "': " << SystemdErrorToString(uid_ret)
                      << '\n';
            continue;
        }

        auto& user_info = users[uid];
        user_info.uid = uid;

        if (user_info.username.empty() || user_info.username == "unknown") {
            user_info.username = GetSessionUsername(session_id, uid);
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
        record["uid"] = uid;
        record["username"] = user_info.username;
        record["sessions"] = std::move(sessions);

        records.push_back(std::move(record));
    }

    return records;
}

void WriteAuthedUsersJson(
    const AuthedUsersByUid& users,
    const std::filesystem::path& output_path
) {
    std::ofstream output(output_path, std::ios::out | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error{"failed to open output file: " + output_path.string()};
    }

    output << ToJson(users).dump(4) << '\n';
    output.close();

    if (!output.good()) {
        throw std::runtime_error{"failed to write output file: " + output_path.string()};
    }
}

int WriteCurrentAuthedUsersInfo(const std::filesystem::path& output_path) {
    try {
        const AuthedUsersByUid users = CollectAuthedUsersFromSystem();
        WriteAuthedUsersJson(users, output_path);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << '\n';
        return 1;
    }
}

int main(int argc, char* argv[]) {
    const std::filesystem::path output_path = std::filesystem::path{"authed_users.json"};

    return WriteCurrentAuthedUsersInfo(output_path);
}