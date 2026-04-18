#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// core/config_watcher.h — Watches config file for changes using inotify
// ─────────────────────────────────────────────────────────────────────────────
//
// Uses Linux inotify to monitor the config JSON file.  When the file is
// modified, the new config is loaded and a user-provided callback is invoked.
//
// THREAD SAFETY:
//   The watcher runs in a dedicated jthread.  The callback is invoked from
//   that thread, so it must be safe to call from a background thread.
// ─────────────────────────────────────────────────────────────────────────────

#include "core/config.h"

#include <functional>
#include <string>
#include <thread>

namespace sysmon {

class ConfigWatcher {
public:
    using Callback = std::function<void(const Config&)>;

    /// @param config_path  Path to the config JSON file
    /// @param on_change    Callback invoked when config changes
    explicit ConfigWatcher(const std::string& config_path, Callback on_change);
    ~ConfigWatcher();

    /// Start watching (spawns a background thread)
    void start();

    /// Stop watching
    void stop();

private:
    std::string config_path_;
    Callback on_change_;
    std::jthread watch_thread_;
    int inotify_fd_ = -1;
    int watch_fd_ = -1;

    void watchLoop(std::stop_token stop_token);
};

} // namespace sysmon
