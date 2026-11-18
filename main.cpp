#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <unordered_set>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "monitor.skel.h"

const std::string CONFIG_FILE = "monitor.conf";
const std::string SERVICE_FILE = "/etc/systemd/system/ebpf-monitor.service";

enum class ViewMode { ALL, TASK, NET, DAEMON };
enum class AlertCategory { SYSTEM, TASK, NET };

struct AlertItem {
    AlertCategory category;
    std::string message;
};

struct PortRange {
    uint16_t start;
    uint16_t end;
    bool contains(uint16_t port) const {
        return port >= start && port <= end;
    }
};

struct MonitorConfig {
    bool autostart = false;
    int interval_sec = 2;
    double alert_tx_kbps = 200.0;
    double alert_rx_kbps = 500.0;
    double soft_total_trigger_mb = 25.0;
    uint64_t soft_high_limit_mb = 60;
    double hard_anon_trigger_mb = 45.0;
    uint64_t hard_max_limit_mb = 80;
    double disk_rw_alert_mb = 25.0;
    std::vector<PortRange> alert_ports = {{1, 65535}};
    std::vector<PortRange> suspicious_ports = {{20, 25}, {3333, 3333}, {4444, 4444}, {6660, 6670}, {9001, 9001}};
    std::unordered_set<std::string> ignore_ips = {"127.0.0.1", "172.17.0.1"};
};

static volatile bool running = true;
void sig_handler(int sig) { running = false; }

struct ContainerInfo {
    std::string name;
    std::string image;
    std::string cgroup_path;
    uint64_t total_bytes = 0;
    uint64_t anon_bytes = 0;
    uint64_t file_bytes = 0;
    uint64_t disk_rw_bytes = 0;
    std::string mem_high_str = "max";
    std::string mem_max_str = "max";
    double cpu_percent = 0.0;
};

struct FlowPrev {
    uint64_t tx_bytes;
    uint64_t rx_bytes;
};

struct DisplayFlow {
    std::string cname;
    std::string proto;
    std::string src_ip;
    std::string dst_ip;
    std::string dst_ep;
    bool is_ephemeral = false;
    int conns = 0;
    double tx_kb = 0.0;
    double rx_kb = 0.0;
    double tx_kbps = 0.0;
    double rx_kbps = 0.0;
};

struct RingBufCtx {
    std::unordered_map<uint64_t, ContainerInfo>* containers;
    std::vector<AlertItem>* recent_alerts;
};

std::string trim(const std::string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::toupper(c); });
    return s;
}

std::string current_time_str() {
    std::time_t now = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

std::string ip_to_str(__u32 ip) {
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::string proto_to_str(__u8 proto) {
    if (proto == PROTO_TCP) return "TCP";
    if (proto == PROTO_UDP) return "UDP";
    return std::to_string(proto);
}

void write_alert_log(const std::string& msg) {
    std::ofstream log_file("alerts.log", std::ios::app);
    if (log_file.is_open()) {
        log_file << "[" << current_time_str() << "] " << msg << "\n";
    }
}

void push_alert(std::vector<AlertItem>& alerts, AlertCategory cat, const std::string& msg) {
    alerts.push_back({cat, "[" + current_time_str() + "] " + msg});
    write_alert_log(msg);
}

bool parse_port_ranges(const std::string& raw, std::vector<PortRange>& out) {
    std::vector<PortRange> parsed;
    std::stringstream ss(raw);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = trim(item);
        if (item.empty()) continue;

        size_t dash = item.find('-');
        try {
            if (dash != std::string::npos) {
                int a = std::stoi(trim(item.substr(0, dash)));
                int b = std::stoi(trim(item.substr(dash + 1)));
                if (a < 0 || a > 65535 || b < 0 || b > 65535) return false;
                if (a > b) std::swap(a, b);
                parsed.push_back({(uint16_t)a, (uint16_t)b});
            } else {
                int p = std::stoi(item);
                if (p < 0 || p > 65535) return false;
                parsed.push_back({(uint16_t)p, (uint16_t)p});
            }
        } catch (...) {
            return false;
        }
    }
    out = std::move(parsed);
    return true;
}

std::string port_ranges_to_string(const std::vector<PortRange>& ranges) {
    std::ostringstream oss;
    for (size_t i = 0; i < ranges.size(); ++i) {
        if (i > 0) oss << ",";
        if (ranges[i].start == ranges[i].end)
            oss << ranges[i].start;
        else
            oss << ranges[i].start << "-" << ranges[i].end;
    }
    return oss.str();
}

bool port_in_ranges(uint16_t port, const std::vector<PortRange>& ranges) {
    for (const auto& r : ranges) {
        if (r.contains(port)) return true;
    }
    return false;
}

std::string str_set_to_string(const std::unordered_set<std::string>& items) {
    std::vector<std::string> sorted_items(items.begin(), items.end());
    std::sort(sorted_items.begin(), sorted_items.end());
    std::ostringstream oss;
    for (size_t i = 0; i < sorted_items.size(); ++i) {
        if (i > 0) oss << ",";
        oss << sorted_items[i];
    }
    return oss.str();
}

bool sync_autostart(bool enable) {
    if (enable) {
        char exe_path[1024] = {};
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len <= 0) return false;
        std::string bin_path(exe_path, len);
        size_t slash = bin_path.find_last_of('/');
        std::string work_dir = (slash != std::string::npos) ? bin_path.substr(0, slash) : ".";

        std::ofstream svc(SERVICE_FILE);
        if (!svc.is_open()) return false;
        svc << "[Unit]\n"
            << "Description=Docker Task Monitor & eBPF Security Monitor\n"
            << "After=local-fs.target\n"
            << "Before=docker.service\n\n"
            << "[Service]\n"
            << "Type=simple\n"
            << "WorkingDirectory=" << work_dir << "\n"
            << "ExecStart=" << bin_path << " --daemon\n"
            << "Restart=always\n"
            << "RestartSec=3\n\n"
            << "[Install]\n"
            << "WantedBy=multi-user.target\n";
        svc.close();

        if (svc.fail()) return false;
        int rc = std::system("systemctl daemon-reload >/dev/null 2>&1 && systemctl enable ebpf-monitor.service >/dev/null 2>&1");
        return rc == 0;
    } else {
        std::system("systemctl disable --now ebpf-monitor.service >/dev/null 2>&1");
        return true;
    }
}

bool save_config(const std::string& path, const MonitorConfig& cfg) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << "# ===================================================================\n"
      << "# Docker Task Monitor & eBPF Security Monitor Configuration\n"
      << "# Changes are applied automatically (Hot-Reload) without restarting.\n"
      << "# ===================================================================\n\n"
      << "# Start monitor automatically on boot before Docker daemon (true/false)\n"
      << "AUTOSTART=" << (cfg.autostart ? "true" : "false") << "\n\n"
      << "# Screen refresh and rule check interval (seconds)\n"
      << "INTERVAL_SEC=" << cfg.interval_sec << "\n\n"
      << "# Outbound traffic (TX) alert threshold (KB/s)\n"
      << "ALERT_TX_KBPS=" << cfg.alert_tx_kbps << "\n\n"
      << "# Inbound traffic (RX) alert threshold (KB/s)\n"
      << "ALERT_RX_KBPS=" << cfg.alert_rx_kbps << "\n\n"
      << "# Level 1 (Soft): Total RAM threshold (anon+cache) to set memory.high (MB)\n"
      << "SOFT_TOTAL_TRIGGER_MB=" << cfg.soft_total_trigger_mb << "\n\n"
      << "# Soft memory.high limit to reclaim file cache without killing container (MB)\n"
      << "SOFT_HIGH_LIMIT_MB=" << cfg.soft_high_limit_mb << "\n\n"
      << "# Level 2 (Hard): Process heap memory (anon) threshold for leak detection (MB)\n"
      << "HARD_ANON_TRIGGER_MB=" << cfg.hard_anon_trigger_mb << "\n\n"
      << "# Hard emergency memory.max limit on ANON leak (MB)\n"
      << "HARD_MAX_LIMIT_MB=" << cfg.hard_max_limit_mb << "\n\n"
      << "# Container writable layer disk usage threshold SizeRw (MB)\n"
      << "DISK_RW_ALERT_MB=" << cfg.disk_rw_alert_mb << "\n\n"
      << "# Ports/ranges (e.g. 80,443,8000-9000) monitored for speed alerts\n"
      << "ALERT_PORTS=" << port_ranges_to_string(cfg.alert_ports) << "\n\n"
      << "# Suspicious ports/ranges (e.g. 20-25,3333,4444) triggering security alerts\n"
      << "SUSPICIOUS_PORTS=" << port_ranges_to_string(cfg.suspicious_ports) << "\n\n"
      << "# Comma-separated whitelist of IP addresses ignored by network alerts\n"
      << "IGNORE_IPS=" << str_set_to_string(cfg.ignore_ips) << "\n";
    return !f.fail();
}

bool apply_config_kv(MonitorConfig& cfg, const std::string& raw_key, const std::string& raw_val) {
    std::string key = to_upper(trim(raw_key));
    std::string val = trim(raw_val);
    try {
        if (key == "AUTOSTART") {
            std::string uval = to_upper(val);
            if (uval == "TRUE" || uval == "1" || uval == "YES" || uval == "ON") cfg.autostart = true;
            else if (uval == "FALSE" || uval == "0" || uval == "NO" || uval == "OFF") cfg.autostart = false;
            else return false;
        }
        else if (key == "INTERVAL_SEC") cfg.interval_sec = std::max(1, std::stoi(val));
        else if (key == "ALERT_TX_KBPS") cfg.alert_tx_kbps = std::stod(val);
        else if (key == "ALERT_RX_KBPS") cfg.alert_rx_kbps = std::stod(val);
        else if (key == "SOFT_TOTAL_TRIGGER_MB") cfg.soft_total_trigger_mb = std::stod(val);
        else if (key == "SOFT_HIGH_LIMIT_MB") cfg.soft_high_limit_mb = std::stoull(val);
        else if (key == "HARD_ANON_TRIGGER_MB") cfg.hard_anon_trigger_mb = std::stod(val);
        else if (key == "HARD_MAX_LIMIT_MB") cfg.hard_max_limit_mb = std::stoull(val);
        else if (key == "DISK_RW_ALERT_MB") cfg.disk_rw_alert_mb = std::stod(val);
        else if (key == "ALERT_PORTS") return parse_port_ranges(val, cfg.alert_ports);
        else if (key == "SUSPICIOUS_PORTS") return parse_port_ranges(val, cfg.suspicious_ports);
        else if (key == "IGNORE_IPS") {
            cfg.ignore_ips.clear();
            std::stringstream ss(val);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item = trim(item);
                if (!item.empty()) cfg.ignore_ips.insert(item);
            }
        } else {
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

void load_config(const std::string& path, MonitorConfig& cfg) {
    std::ifstream f(path);
    if (!f.is_open()) {
        save_config(path, cfg);
        return;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            apply_config_kv(cfg, line.substr(0, eq), line.substr(eq + 1));
        }
    }
}

time_t get_file_mtime(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return st.st_mtime;
    return 0;
}

void print_config(const MonitorConfig& cfg) {
    std::cout << "=== Current Configuration (" << CONFIG_FILE << ") ===\n"
              << "  AUTOSTART             = " << (cfg.autostart ? "true" : "false") << "\n"
              << "  INTERVAL_SEC          = " << cfg.interval_sec << " sec\n"
              << "  ALERT_TX_KBPS         = " << cfg.alert_tx_kbps << " KB/s\n"
              << "  ALERT_RX_KBPS         = " << cfg.alert_rx_kbps << " KB/s\n"
              << "  SOFT_TOTAL_TRIGGER_MB = " << cfg.soft_total_trigger_mb << " MB\n"
              << "  SOFT_HIGH_LIMIT_MB    = " << cfg.soft_high_limit_mb << " MB\n"
              << "  HARD_ANON_TRIGGER_MB  = " << cfg.hard_anon_trigger_mb << " MB\n"
              << "  HARD_MAX_LIMIT_MB     = " << cfg.hard_max_limit_mb << " MB\n"
              << "  DISK_RW_ALERT_MB      = " << cfg.disk_rw_alert_mb << " MB\n"
              << "  ALERT_PORTS           = " << port_ranges_to_string(cfg.alert_ports) << "\n"
              << "  SUSPICIOUS_PORTS      = " << port_ranges_to_string(cfg.suspicious_ports) << "\n"
              << "  IGNORE_IPS            = " << str_set_to_string(cfg.ignore_ips) << "\n";
}

uint64_t read_uint64_file(const std::string& path) {
    std::ifstream f(path);
    uint64_t val = 0;
    if (f.is_open()) f >> val;
    return val;
}

void read_memory_stat(const std::string& cgroup_path, uint64_t& anon_bytes, uint64_t& file_bytes) {
    std::ifstream f(cgroup_path + "/memory.stat");
    std::string key;
    uint64_t val = 0;
    anon_bytes = 0;
    file_bytes = 0;
    while (f >> key >> val) {
        if (key == "anon") anon_bytes = val;
        else if (key == "file") file_bytes = val;
    }
}

std::string read_mem_limit_str(const std::string& file_path) {
    std::ifstream f(file_path);
    std::string val = "unknown";
    if (f.is_open()) {
        f >> val;
        if (val != "max") {
            try {
                double mb = std::stoull(val) / (1024.0 * 1024.0);
                std::ostringstream oss;
                oss << std::fixed << std::setprecision(0) << mb << "M";
                return oss.str();
            } catch (...) {}
        }
    }
    return val;
}

uint64_t read_cpu_usec(const std::string& cgroup_path) {
    std::ifstream f(cgroup_path + "/cpu.stat");
    std::string key;
    uint64_t val = 0;
    while (f >> key >> val) {
        if (key == "usage_usec") return val;
    }
    return 0;
}

bool write_cgroup_limit_raw(const std::string& file_path, const std::string& raw_val) {
    std::ofstream f(file_path);
    if (!f.is_open()) return false;
    f << raw_val;
    f.flush();
    return !f.fail();
}

bool set_mem_limit_mb(const std::string& file_path, uint64_t limit_mb) {
    return write_cgroup_limit_raw(file_path, std::to_string(limit_mb * 1024ULL * 1024ULL));
}

std::unordered_map<uint64_t, ContainerInfo> get_docker_containers(
    std::unordered_map<uint64_t, uint64_t>& prev_cpu_usec, int interval_sec, bool with_disk_size = true)
{
    std::unordered_map<uint64_t, ContainerInfo> result;
    const char* cmd = with_disk_size
        ? "sh -c 'for id in $(docker ps -q 2>/dev/null); do "
          "docker inspect -s -f \"{{.State.Pid}} {{.Name}} {{.Config.Image}} {{if .SizeRw}}{{.SizeRw}}{{else}}0{{end}}\" $id; done'"
        : "sh -c 'for id in $(docker ps -q 2>/dev/null); do "
          "docker inspect -f \"{{.State.Pid}} {{.Name}} {{.Config.Image}} 0\" $id; done'";

    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;

    char line[512];
    while (fgets(line, sizeof(line), pipe)) {
        std::istringstream iss(line);
        int pid;
        std::string name, image;
        uint64_t rw_bytes = 0;
        if (!(iss >> pid >> name >> image >> rw_bytes) || pid == 0) continue;
        if (!name.empty() && name[0] == '/') name.erase(0, 1);

        std::ifstream cg_file("/proc/" + std::to_string(pid) + "/cgroup");
        std::string cg_line;
        while (std::getline(cg_file, cg_line)) {
            if (cg_line.rfind("0::", 0) == 0) {
                std::string full_path = "/sys/fs/cgroup" + cg_line.substr(3);
                struct stat st;
                if (stat(full_path.c_str(), &st) == 0) {
                    ContainerInfo info;
                    info.name = name;
                    info.image = image;
                    info.cgroup_path = full_path;
                    info.disk_rw_bytes = rw_bytes;
                    info.total_bytes = read_uint64_file(full_path + "/memory.current");
                    read_memory_stat(full_path, info.anon_bytes, info.file_bytes);
                    info.mem_high_str = read_mem_limit_str(full_path + "/memory.high");
                    info.mem_max_str  = read_mem_limit_str(full_path + "/memory.max");

                    uint64_t cur_cpu = read_cpu_usec(full_path);
                    if (prev_cpu_usec.count(st.st_ino) && cur_cpu >= prev_cpu_usec[st.st_ino]) {
                        uint64_t delta_usec = cur_cpu - prev_cpu_usec[st.st_ino];
                        info.cpu_percent = (delta_usec / (interval_sec * 1000000.0)) * 100.0;
                    }
                    prev_cpu_usec[st.st_ino] = cur_cpu;

                    result[st.st_ino] = info;
                }
                break;
            }
        }
    }
    pclose(pipe);
    return result;
}

static int handle_file_event(void *ctx, void *data, size_t data_sz) {
    auto *rb_ctx = static_cast<RingBufCtx*>(ctx);
    const auto *ev = static_cast<const struct file_event_t*>(data);

    auto it = rb_ctx->containers->find(ev->cgroup_id);
    if (it == rb_ctx->containers->end()) return 0;

    std::string proc_name(ev->comm);
    if (proc_name.rfind("runc", 0) == 0) return 0;

    bool is_write = (ev->flags & (1 | 2 | 64 | 512)) != 0;
    std::string mode = is_write ? "WRITE" : "READ";
    std::string alert = "[CRITICAL PATH " + mode + "] Container '" + it->second.name +
                        "' (process '" + proc_name + "', PID=" + std::to_string(ev->pid) +
                        ") accessed '" + std::string(ev->filename) + "'";
    push_alert(*rb_ctx->recent_alerts, AlertCategory::TASK, alert);
    return 0;
}

void print_usage() {
    std::cout << "Usage:\n"
              << "  sudo ./monitor                 - Full real-time monitor (Tasks + Network + All Alerts)\n"
              << "  sudo ./monitor showtask        - Real-time Task Monitor (RAM, Disk RW, FS & Memory Alerts)\n"
              << "  sudo ./monitor shownet         - Real-time Network Monitor (TCP/UDP Flows & Net Alerts)\n"
              << "  sudo ./monitor --daemon        - Background daemon mode (no TUI output)\n"
              << "  sudo ./monitor config          - Show current configuration\n"
              << "  sudo ./monitor set KEY=VAL ... - Update configuration (supports hot-reload & AUTOSTART)\n"
              << "  sudo ./monitor limit NAME MB   - Manually set or reset (max) container memory.max\n";
}

int handle_cli_commands(int argc, char* argv[], ViewMode& mode_out) {
    std::string cmd = argv[1];
    if (cmd == "showtask" || cmd == "--showtask") {
        mode_out = ViewMode::TASK;
        return -1;
    }
    if (cmd == "shownet" || cmd == "--shownet") {
        mode_out = ViewMode::NET;
        return -1;
    }
    if (cmd == "--daemon" || cmd == "daemon") {
        mode_out = ViewMode::DAEMON;
        return -1;
    }

    MonitorConfig cfg;
    load_config(CONFIG_FILE, cfg);
    bool old_autostart = cfg.autostart;

    if (cmd == "config" || cmd == "--config") {
        print_config(cfg);
        return 0;
    }
    if (cmd == "set" || cmd == "--set") {
        if (argc < 3) {
            std::cerr << "Usage: sudo ./monitor set KEY=VALUE ...\n";
            return 1;
        }
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            size_t eq = arg.find('=');
            if (eq == std::string::npos || !apply_config_kv(cfg, arg.substr(0, eq), arg.substr(eq + 1))) {
                std::cerr << "[-] Invalid parameter: " << arg << "\n";
                return 1;
            }
        }
        if (!save_config(CONFIG_FILE, cfg)) {
            std::cerr << "[-] Failed to write " << CONFIG_FILE << ". Run with sudo!\n";
            return 1;
        }
        if (cfg.autostart != old_autostart) {
            if (sync_autostart(cfg.autostart)) {
                std::cout << "[+] Autostart (before docker.service) "
                          << (cfg.autostart ? "ENABLED" : "DISABLED") << "!\n";
            } else {
                std::cerr << "[-] Failed to configure systemd autostart. Run with sudo!\n";
            }
        }
        std::cout << "[+] Configuration updated!\n\n";
        print_config(cfg);
        return 0;
    }
    if (cmd == "limit" || cmd == "--limit") {
        if (argc < 4) {
            std::cerr << "Usage: sudo ./monitor limit <container> <MB | max>\n";
            return 1;
        }
        std::string target_name = argv[2];
        std::string target_val = argv[3];
        std::unordered_map<uint64_t, uint64_t> dummy_cpu;
        auto containers = get_docker_containers(dummy_cpu, 1, false);
        for (const auto& [cg_id, c] : containers) {
            if (c.name == target_name) {
                std::string raw_bytes;
                if (target_val == "max") {
                    raw_bytes = "max";
                    write_cgroup_limit_raw(c.cgroup_path + "/memory.high", "max");
                } else {
                    try {
                        raw_bytes = std::to_string(std::stoull(target_val) * 1024ULL * 1024ULL);
                    } catch (...) {
                        std::cerr << "[-] Specify size in MB or 'max'.\n";
                        return 1;
                    }
                }
                if (write_cgroup_limit_raw(c.cgroup_path + "/memory.max", raw_bytes)) {
                    std::cout << "[+] Set memory.max = " << target_val << " for '" << target_name << "'\n";
                    return 0;
                }
            }
        }
        std::cerr << "[-] Active container '" << target_name << "' not found.\n";
        return 1;
    }

    print_usage();
    return 1;
}

int main(int argc, char* argv[]) {
    ViewMode view_mode = ViewMode::ALL;
    if (argc > 1) {
        int cli_res = handle_cli_commands(argc, argv, view_mode);
        if (cli_res >= 0) return cli_res;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    MonitorConfig cfg;
    load_config(CONFIG_FILE, cfg);
    bool prev_autostart = cfg.autostart;
    time_t last_cfg_mtime = get_file_mtime(CONFIG_FILE);

    struct monitor_bpf *skel = monitor_bpf__open_and_load();
    if (!skel) {
        std::cerr << "[-] Failed to open/load eBPF skeleton! Run with sudo.\n";
        return 1;
    }
    if (monitor_bpf__attach(skel) != 0) {
        std::cerr << "[-] Failed to attach eBPF hooks!\n";
        monitor_bpf__destroy(skel);
        return 1;
    }

    int map_fd = bpf_map__fd(skel->maps.traffic_map);
    std::unordered_map<uint64_t, uint64_t> prev_cpu_usec;
    std::unordered_map<std::string, FlowPrev> prev_flows;
    std::unordered_set<std::string> logged_port_alerts;
    std::unordered_set<uint64_t> soft_limited_cgs;
    std::unordered_set<uint64_t> hard_limited_cgs;
    std::unordered_set<uint64_t> disk_alerted_cgs;
    std::vector<AlertItem> recent_alerts;

    auto containers = get_docker_containers(prev_cpu_usec, cfg.interval_sec, view_mode != ViewMode::NET);
    RingBufCtx rb_ctx{&containers, &recent_alerts};

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.file_events_rb), handle_file_event, &rb_ctx, nullptr);
    if (!rb) {
        std::cerr << "[-] Failed to create RingBuffer!\n";
        monitor_bpf__destroy(skel);
        return 1;
    }

    while (running) {
        int steps = std::max(1, (cfg.interval_sec * 1000) / 200);
        for (int s = 0; s < steps && running; ++s) {
            ring_buffer__poll(rb, 200);
        }
        if (!running) break;

        time_t cur_mtime = get_file_mtime(CONFIG_FILE);
        if (cur_mtime != 0 && cur_mtime != last_cfg_mtime) {
            load_config(CONFIG_FILE, cfg);
            last_cfg_mtime = cur_mtime;
            soft_limited_cgs.clear();
            hard_limited_cgs.clear();
            disk_alerted_cgs.clear();
            logged_port_alerts.clear();

            if (cfg.autostart != prev_autostart) {
                sync_autostart(cfg.autostart);
                prev_autostart = cfg.autostart;
                push_alert(recent_alerts, AlertCategory::SYSTEM,
                           std::string("[AUTOSTART] Boot service ") + (cfg.autostart ? "ENABLED" : "DISABLED"));
            }
            push_alert(recent_alerts, AlertCategory::SYSTEM,
                       "[CONFIG RELOADED] Rules updated from " + CONFIG_FILE);
        }

        containers = get_docker_containers(prev_cpu_usec, cfg.interval_sec, view_mode != ViewMode::NET);

        for (auto& [cg_id, c] : containers) {
            double total_mb = c.total_bytes   / (1024.0 * 1024.0);
            double anon_mb  = c.anon_bytes    / (1024.0 * 1024.0);
            double disk_mb  = c.disk_rw_bytes / (1024.0 * 1024.0);

            if (total_mb > cfg.soft_total_trigger_mb) {
                if (!soft_limited_cgs.count(cg_id) && c.mem_high_str != std::to_string(cfg.soft_high_limit_mb) + "M") {
                    if (set_mem_limit_mb(c.cgroup_path + "/memory.high", cfg.soft_high_limit_mb)) {
                        soft_limited_cgs.insert(cg_id);
                        c.mem_high_str = std::to_string(cfg.soft_high_limit_mb) + "M";
                        push_alert(recent_alerts, AlertCategory::TASK,
                                   "[MEM LEVEL 1: SOFT] '" + c.name + "' (Total=" + std::to_string((int)total_mb) +
                                   "M) -> memory.high=" + std::to_string(cfg.soft_high_limit_mb) + "M");
                    }
                }
            }

            if (anon_mb > cfg.hard_anon_trigger_mb) {
                if (!hard_limited_cgs.count(cg_id) && c.mem_max_str != std::to_string(cfg.hard_max_limit_mb) + "M") {
                    if (set_mem_limit_mb(c.cgroup_path + "/memory.max", cfg.hard_max_limit_mb)) {
                        hard_limited_cgs.insert(cg_id);
                        c.mem_max_str = std::to_string(cfg.hard_max_limit_mb) + "M";
                        push_alert(recent_alerts, AlertCategory::TASK,
                                   "[MEM LEVEL 2: HARD] '" + c.name + "' ANON=" +
                                   std::to_string((int)anon_mb) + "M -> memory.max=" +
                                   std::to_string(cfg.hard_max_limit_mb) + "M");
                    }
                }
            }

            if (view_mode != ViewMode::NET && disk_mb > cfg.disk_rw_alert_mb) {
                if (!disk_alerted_cgs.count(cg_id)) {
                    disk_alerted_cgs.insert(cg_id);
                    push_alert(recent_alerts, AlertCategory::TASK,
                               "[DISK RW ALERT] '" + c.name + "' wrote " +
                               std::to_string((int)disk_mb) + " MB to writable layer");
                }
            }
        }

        std::unordered_map<std::string, DisplayFlow> aggregated_flows;
        struct traffic_key_t key = {}, next_key = {};
        struct traffic_key_t *cur_key = nullptr;

        while (bpf_map_get_next_key(map_fd, cur_key, &next_key) == 0) {
            auto it = containers.find(next_key.cgroup_id);
            if (it != containers.end()) {
                struct traffic_val_t val = {};
                if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
                    std::string cname = it->second.name;
                    std::string proto_str = proto_to_str(next_key.proto);
                    std::string src_ip = ip_to_str(next_key.saddr);
                    std::string dst_ip = ip_to_str(next_key.daddr);
                    std::string dst_ep = dst_ip + ":" + std::to_string(next_key.dport);
                    std::string flow_id = std::to_string(next_key.cgroup_id) + "|" + proto_str + "|" + src_ip + "|" + dst_ep;

                    uint64_t prev_tx = 0, prev_rx = 0;
                    if (prev_flows.count(flow_id)) {
                        prev_tx = prev_flows[flow_id].tx_bytes;
                        prev_rx = prev_flows[flow_id].rx_bytes;
                    }
                    prev_flows[flow_id] = {val.tx_bytes, val.rx_bytes};

                    double tx_kbps = (val.tx_bytes - prev_tx) / 1024.0 / cfg.interval_sec;
                    double rx_kbps = (val.rx_bytes - prev_rx) / 1024.0 / cfg.interval_sec;

                    bool ip_ignored = cfg.ignore_ips.count(src_ip) || cfg.ignore_ips.count(dst_ip);
                    if (!ip_ignored) {
                        if (port_in_ranges(next_key.dport, cfg.alert_ports)) {
                            if (tx_kbps > cfg.alert_tx_kbps) {
                                push_alert(recent_alerts, AlertCategory::NET,
                                           "[HIGH TX " + proto_str + "] '" + cname + "' -> " + dst_ep +
                                           " (" + std::to_string((int)tx_kbps) + " KB/s)");
                            }
                            if (rx_kbps > cfg.alert_rx_kbps) {
                                push_alert(recent_alerts, AlertCategory::NET,
                                           "[HIGH RX " + proto_str + "] '" + cname + "' <- " + dst_ep +
                                           " (" + std::to_string((int)rx_kbps) + " KB/s)");
                            }
                        }
                        if (port_in_ranges(next_key.dport, cfg.suspicious_ports) && !logged_port_alerts.count(flow_id)) {
                            logged_port_alerts.insert(flow_id);
                            push_alert(recent_alerts, AlertCategory::NET,
                                       "[SUSPICIOUS PORT " + proto_str + "] '" + cname + "' -> port " +
                                       std::to_string(next_key.dport) + " (" + dst_ip + ")");
                        }
                    }

                    bool is_ephem = (next_key.dport >= 32768);
                    std::string disp_key = cname + "|" + proto_str + "|" + src_ip + "|" + dst_ip + "|" +
                                           (is_ephem ? "EPHEM" : std::to_string(next_key.dport));

                    auto& df = aggregated_flows[disp_key];
                    if (df.conns == 0) {
                        df.cname = cname;
                        df.proto = proto_str;
                        df.src_ip = src_ip;
                        df.dst_ip = dst_ip;
                        df.dst_ep = dst_ep;
                        df.is_ephemeral = is_ephem;
                    }
                    df.conns++;
                    df.tx_kb += (val.tx_bytes / 1024.0);
                    df.rx_kb += (val.rx_bytes / 1024.0);
                    df.tx_kbps += tx_kbps;
                    df.rx_kbps += rx_kbps;
                }
            }
            key = next_key;
            cur_key = &key;
        }

        if (view_mode == ViewMode::DAEMON) {
            if (recent_alerts.size() > 50) recent_alerts.erase(recent_alerts.begin(), recent_alerts.end() - 50);
            continue;
        }

        std::ostringstream out;
        std::string title_mode = (view_mode == ViewMode::TASK) ? "TASK MONITOR MODE" :
                                 (view_mode == ViewMode::NET)  ? "NETWORK MONITOR MODE" :
                                                                 "FULL MONITOR MODE";

        out << "=== Docker Task & eBPF Security Monitor [" << title_mode << "] ===\n";
        out << "Autostart=[" << (cfg.autostart ? "ON" : "OFF")
            << "] | AlertPorts=[" << port_ranges_to_string(cfg.alert_ports)
            << "] | SuspPorts=[" << port_ranges_to_string(cfg.suspicious_ports)
            << "] | IgnoreIPs=[" << str_set_to_string(cfg.ignore_ips) << "]\n\n";

        if (view_mode == ViewMode::ALL || view_mode == ViewMode::TASK) {
            out << "\033[1;36m[ TASK MONITOR (RAM anon/cache & Writable Disk Layer) ]\033[0m\n";
            out << std::left
                << std::setw(15) << "CONTAINER"
                << std::setw(8)  << "CPU%"
                << std::setw(10) << "ANON(M)"
                << std::setw(10) << "CACHE(M)"
                << std::setw(11) << "DISK_RW(M)"
                << std::setw(8)  << "HIGH"
                << std::setw(8)  << "MAX"
                << std::setw(15) << "CONTROL" << "\n";
            out << std::string(85, '-') << "\n";

            for (const auto& [cg_id, c] : containers) {
                double total_mb = c.total_bytes   / (1024.0 * 1024.0);
                double anon_mb  = c.anon_bytes    / (1024.0 * 1024.0);
                double file_mb  = c.file_bytes    / (1024.0 * 1024.0);
                double disk_mb  = c.disk_rw_bytes / (1024.0 * 1024.0);
                std::string status = "OK";
                if (anon_mb > cfg.hard_anon_trigger_mb) status = "HARD LIMIT!";
                else if (total_mb > cfg.soft_total_trigger_mb) status = "SOFT LIMIT";
                else if (disk_mb > cfg.disk_rw_alert_mb) status = "DISK ALERT!";

                out << std::left
                    << std::setw(15) << c.name.substr(0, 14)
                    << std::setw(8)  << std::fixed << std::setprecision(1) << c.cpu_percent
                    << std::setw(10) << std::fixed << std::setprecision(2) << anon_mb
                    << std::setw(10) << std::fixed << std::setprecision(2) << file_mb
                    << std::setw(11) << std::fixed << std::setprecision(2) << disk_mb
                    << std::setw(8)  << c.mem_high_str
                    << std::setw(8)  << c.mem_max_str
                    << std::setw(15) << status << "\n";
            }
            out << "\n";
        }

        std::vector<std::string> filtered_alerts;
        for (const auto& a : recent_alerts) {
            if (view_mode == ViewMode::ALL ||
                a.category == AlertCategory::SYSTEM ||
                (view_mode == ViewMode::TASK && a.category == AlertCategory::TASK) ||
                (view_mode == ViewMode::NET && a.category == AlertCategory::NET)) {
                filtered_alerts.push_back(a.message);
            }
        }

        if (!filtered_alerts.empty()) {
            out << "\033[1;31m[ SECURITY & CONTROL ALERTS (alerts.log) ]\033[0m\n";
            int start = std::max(0, (int)filtered_alerts.size() - 8);
            for (int i = start; i < (int)filtered_alerts.size(); ++i) {
                out << "\033[1;31m! " << filtered_alerts[i] << "\033[0m\n";
            }
            out << "\n";
        }

        if (view_mode == ViewMode::ALL || view_mode == ViewMode::NET) {
            std::vector<DisplayFlow> sorted_flows;
            sorted_flows.reserve(aggregated_flows.size());
            for (auto& [k, v] : aggregated_flows) {
                if (v.is_ephemeral && v.conns > 1) {
                    v.dst_ep = v.dst_ip + ":* (" + std::to_string(v.conns) + ")";
                }
                sorted_flows.push_back(std::move(v));
            }

            std::sort(sorted_flows.begin(), sorted_flows.end(), [](const DisplayFlow& a, const DisplayFlow& b) {
                return (a.tx_kb + a.rx_kb) > (b.tx_kb + b.rx_kb);
            });

            out << "\033[1;32m[ NETWORK TRAFFIC (eBPF TCP & UDP - " << sorted_flows.size() << " flows) ]\033[0m\n";
            out << std::left
                << std::setw(14) << "CONTAINER"
                << std::setw(7)  << "PROTO"
                << std::setw(16) << "SRC IP"
                << std::setw(22) << "DST IP:PORT"
                << std::setw(10) << "TX (KB)"
                << std::setw(10) << "RX (KB)"
                << std::setw(10) << "TX KB/s"
                << std::setw(10) << "RX KB/s" << "\n";
            out << std::string(99, '-') << "\n";

            for (const auto& f : sorted_flows) {
                out << std::left
                    << std::setw(14) << f.cname.substr(0, 13)
                    << std::setw(7)  << f.proto
                    << std::setw(16) << f.src_ip
                    << std::setw(22) << f.dst_ep.substr(0, 21)
                    << std::setw(10) << std::fixed << std::setprecision(1) << f.tx_kb
                    << std::setw(10) << std::fixed << std::setprecision(1) << f.rx_kb
                    << std::setw(10) << std::fixed << std::setprecision(1) << f.tx_kbps
                    << std::setw(10) << std::fixed << std::setprecision(1) << f.rx_kbps << "\n";
            }
        }

        std::cout << "\033[H\033[2J\033[3J" << out.str() << std::flush;
    }

    if (view_mode != ViewMode::DAEMON) {
        std::cout << "\n[*] Unloading eBPF hooks and exiting...\n";
    }
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return 0;
}
