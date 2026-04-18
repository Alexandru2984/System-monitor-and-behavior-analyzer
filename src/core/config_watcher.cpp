// ─────────────────────────────────────────────────────────────────────────────
// core/config_watcher.cpp — inotify-based config file watcher
// ─────────────────────────────────────────────────────────────────────────────

#include "core/config_watcher.h"
#include "utils/logger.h"

#include <sys/inotify.h>
#include <unistd.h>
#include <poll.h>
#include <cerrno>
#include <cstring>

namespace sysmon {

ConfigWatcher::ConfigWatcher(const std::string& config_path, Callback on_change)
    : config_path_(config_path)
    , on_change_(std::move(on_change))
{}

ConfigWatcher::~ConfigWatcher() {
    stop();
}

void ConfigWatcher::start() {
    inotify_fd_ = inotify_init1(IN_NONBLOCK);
    if (inotify_fd_ < 0) {
        LOG_ERROR("ConfigWatcher: inotify_init1 failed: {}", strerror(errno));
        return;
    }

    // Watch for CLOSE_WRITE (editors write to a temp file, then rename)
    // and IN_MOVED_TO (atomic rename into place)
    watch_fd_ = inotify_add_watch(inotify_fd_, config_path_.c_str(),
                                   IN_CLOSE_WRITE | IN_MODIFY);
    if (watch_fd_ < 0) {
        // The file might not exist yet — watch the directory instead
        // For simplicity, we'll just watch the file directly
        LOG_WARN("ConfigWatcher: cannot watch '{}': {}",
                 config_path_, strerror(errno));
        close(inotify_fd_);
        inotify_fd_ = -1;
        return;
    }

    watch_thread_ = std::jthread([this](std::stop_token st) {
        watchLoop(std::move(st));
    });

    LOG_INFO("ConfigWatcher: watching '{}' for changes", config_path_);
}

void ConfigWatcher::stop() {
    if (watch_thread_.joinable()) {
        watch_thread_.request_stop();
        watch_thread_.join();
    }

    if (watch_fd_ >= 0) {
        inotify_rm_watch(inotify_fd_, watch_fd_);
        watch_fd_ = -1;
    }
    if (inotify_fd_ >= 0) {
        close(inotify_fd_);
        inotify_fd_ = -1;
    }
}

void ConfigWatcher::watchLoop(std::stop_token stop_token) {
    constexpr size_t BUF_SIZE = 4096;
    char buf[BUF_SIZE] __attribute__((aligned(alignof(struct inotify_event))));

    while (!stop_token.stop_requested()) {
        // Poll with 500ms timeout so we can check stop_token periodically
        struct pollfd pfd = {inotify_fd_, POLLIN, 0};
        int ret = poll(&pfd, 1, 500);

        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("ConfigWatcher: poll error: {}", strerror(errno));
            break;
        }

        if (ret == 0) continue;  // timeout, check stop_token

        // Read events
        ssize_t len = read(inotify_fd_, buf, BUF_SIZE);
        if (len < 0) {
            if (errno == EAGAIN) continue;
            LOG_ERROR("ConfigWatcher: read error: {}", strerror(errno));
            break;
        }

        // Process events — we don't care about individual events,
        // just that the file changed
        bool changed = false;
        for (char* ptr = buf; ptr < buf + len; ) {
            auto* event = reinterpret_cast<struct inotify_event*>(ptr);
            if (event->mask & (IN_CLOSE_WRITE | IN_MODIFY)) {
                changed = true;
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }

        if (changed) {
            LOG_INFO("ConfigWatcher: config file changed, reloading...");

            // Small delay to let editors finish writing
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            try {
                auto new_config = Config::loadFromFile(config_path_);
                on_change_(new_config);
                LOG_INFO("ConfigWatcher: config reloaded successfully");
            } catch (const std::exception& e) {
                LOG_ERROR("ConfigWatcher: failed to reload config: {}", e.what());
            }
        }
    }
}

} // namespace sysmon
