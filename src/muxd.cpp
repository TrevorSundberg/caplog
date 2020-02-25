// MIT License, copyright Trevor Sundberg 2020 (see LICENSE)
#include "muxd.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>
#include <regex>
#include <sstream>
#include <streambuf>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "date/date.h"
#include "date/tz.h"

static const char* const kDefaultOutputDir = "/tmp";
static const char* const kDefaultFileRegex = "stdout|stderr";
static const char* const kDefaultFilenameFormat = "%P:%i_%f_%F_%T_%z.log";
static const char* const kDefaultLineFormat = "[%F %T %z] %l%n";
static const char* const kDefaultTimeZone = "UTC";
static const std::regex kProcessModifier("%P");
static const std::regex kPidModifier("%i");
static const std::regex kFileModifier("%f");
static const std::regex kLineModifier("%l");
static const std::string kStdout = "stdout";
static const std::string kStderr = "stderr";
static const size_t kLongSize = sizeof(long);
static const int kIgnoreFd = -2;

#define EXPORT __attribute__((visibility("default"))) extern "C"

#define CHECK(expression)                                                   \
  do {                                                                      \
    if (!(expression)) {                                                    \
      std::cerr << __FILE__ << "(" << __LINE__ << ") in "                   \
                << __PRETTY_FUNCTION__ << ": " << #expression << std::endl; \
      abort();                                                              \
    }                                                                       \
  } while (0)

static int wait_for_syscall(pid_t pid) {
  int status;
  while (1) {
    CHECK(ptrace(PTRACE_SYSCALL, pid, 0, 0) == 0);
    CHECK(waitpid(pid, &status, 0) == pid);
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) return 0;
    if (WIFEXITED(status)) return 1;
  }
}

static void getdataslow(const pid_t pid, const long addr, char* const str,
                        const int len) {
  char* laddr;
  int i, j;
  union u {
    long val;
    char chars[kLongSize];
  } data;
  i = 0;
  j = len / kLongSize;
  laddr = str;
  while (i < j) {
    data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * kLongSize, NULL);
    memcpy(laddr, data.chars, kLongSize);
    ++i;
    laddr += kLongSize;
  }
  j = len % kLongSize;
  if (j != 0) {
    data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * kLongSize, NULL);
    memcpy(laddr, data.chars, j);
  }
}

static void getdata(const pid_t pid, const int mem_fd, const long addr,
                    char* const str, const int len) {
  const ssize_t count = pread(mem_fd, str, len, addr);
  // For some reason if the child process is made by us (fork/exec) and we
  // attach to it, either via PTRACE_ATTACH from the parent or PTRACE_TRACEME
  // from the child, reading from /proc/<pid>/mem always returns EOF (with no
  // errno).
  if (count == len) {
    return;
  }
  getdataslow(pid, addr, str, len);
}

static std::string read_into_string(const std::string& path) {
  std::ifstream ifstream(path);
  return std::string((std::istreambuf_iterator<char>(ifstream)),
                     std::istreambuf_iterator<char>());
}

static std::string get_proc_path(const pid_t pid, const char* const dir) {
  return "/proc/" + std::to_string(pid) + "/" + dir;
}

static void enumerate(const pid_t parent, std::vector<pid_t>& pids) {
  pids.push_back(parent);

  const std::string task_path = get_proc_path(parent, "task/");

  // The std::filesystem::directory_iterator segfaults on "/proc/".
  DIR* const dir = opendir(task_path.c_str());
  CHECK(dir);
  for (;;) {
    const dirent* const ent = readdir(dir);
    if (!ent) {
      break;
    }

    // Check if the entire string is a number (tid).
    char* end = nullptr;
    const pid_t tid = (pid_t)strtoll(ent->d_name, &end, 10);
    if (end - ent->d_name == strlen(ent->d_name)) {
      const std::string children_path =
          task_path + std::to_string(tid) + "/children";
      const std::string children = read_into_string(children_path);

      // For each child we find, recursively enumerate their children.
      std::stringstream children_stream(children);
      std::string child_pid;
      while (children_stream >> child_pid) {
        const pid_t child = (pid_t)std::stoll(child_pid);
        enumerate(child, pids);
      }
    }
  }
  CHECK(closedir(dir) == 0);
}

static std::string format_now(const char* const fmt,
                              const date::time_zone* const time_zone,
                              const std::string& process, const pid_t pid,
                              const std::string& fd_name,
                              const std::string& line = std::string()) {
  std::string result = date::format(
      fmt, date::zoned_time{time_zone, std::chrono::system_clock::now()});
  result = std::regex_replace(result, kProcessModifier, process);
  result = std::regex_replace(result, kPidModifier, std::to_string(pid));
  result = std::regex_replace(result, kFileModifier, fd_name);
  result = std::regex_replace(result, kLineModifier, line);
  return result;
}

std::string get_process_fd_name(const pid_t pid, const int fd) {
  if (fd == 1) {
    return kStdout;
  } else if (fd == 2) {
    return kStderr;
  } else {
    const std::string proc_fd_path =
        get_proc_path(pid, "fd/") + std::to_string(fd);
    char link_path[PATH_MAX] = {0};
    CHECK(readlink(proc_fd_path.c_str(), link_path, sizeof(link_path)) !=
          (ssize_t)-1);
    return link_path;
  }
}

static void rtrim(std::string& s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](int ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

static std::string get_pid_name(pid_t pid) {
  std::string result = read_into_string(get_proc_path(pid, "comm"));
  rtrim(result);
  return result;
}

static void capture(const muxd_info* const info, const pid_t pid) {
  const std::string process = get_pid_name(pid);

  CHECK(waitpid(pid, nullptr, 0) == pid);
  CHECK(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == 0);

  const int mem_fd = open(get_proc_path(pid, "mem").c_str(), O_RDONLY);
  CHECK(mem_fd != -1);

  struct fd_data {
    int output_fd = -1;
    std::string fd_name;
  };

  std::unordered_map<int, fd_data> fds;
  std::vector<char> buffer;
  std::vector<char> lines;

  const date::time_zone* time_zone = info->time_zone && *info->time_zone
                                         ? date::locate_zone(info->time_zone)
                                         : date::current_zone();

  std::regex file_regex(info->file_regex);

  for (;;) {
    CHECK(wait_for_syscall(pid) == 0);

    const long orig_rax =
        ptrace(PTRACE_PEEKUSER, pid, kLongSize * ORIG_RAX, nullptr);
    if (orig_rax == SYS_write) {
      user_regs_struct regs;
      CHECK(ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0);
      const int fd = (int)regs.rdi;
      const long buff = regs.rsi;

      // Wait to exit the syscall.
      CHECK(wait_for_syscall(pid) == 0);

      fd_data& data = fds[fd];
      if (data.output_fd == kIgnoreFd) {
        continue;
      }

      if (data.output_fd == -1) {
        fd_data& data = fds[fd];
        data.fd_name = get_process_fd_name(pid, fd);

        if (std::regex_match(data.fd_name, file_regex)) {
          const std::string log_path =
              std::string(info->output_directory) + "/" +
              format_now(info->filename_format, time_zone, process, pid,
                         data.fd_name);
          data.output_fd = open(log_path.c_str(), O_WRONLY | O_CREAT);
          CHECK(data.output_fd != -1);

          std::cout << "Log created: " << log_path << std::endl;
        } else {
          data.fd_name.clear();
          data.output_fd = kIgnoreFd;
          continue;
        }
      }

      // Figure out how much was actually written to the output (could differ
      // from count/rdx).
      CHECK(ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0);
      const long written = regs.rax;

      buffer.resize(written);
      getdata(pid, mem_fd, buff, buffer.data(), written);

      if (info->line_format && *info->line_format) {
        lines.insert(lines.end(), buffer.begin(), buffer.end());

        const char* start = lines.data();
        for (size_t i = 0; i < lines.size(); ++i) {
          if (lines[i] == '\n') {
            const char* const end = lines.data() + i;
            const std::string line(start, end);
            start = end + 1;
            const std::string formatted = format_now(
                info->line_format, time_zone, process, pid, data.fd_name, line);
            CHECK(write(data.output_fd, formatted.data(), formatted.size()) ==
                  formatted.size());
          }
        }
        lines.erase(lines.begin(), lines.begin() + (start - lines.data()));
      } else {
        CHECK(write(data.output_fd, buffer.data(), written) == written);
      }
    }
  }

  CHECK(close(mem_fd) == 0);
}

static void spawn(const muxd_info* const info, char* argv[]) {
  const pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    // Make sure we die if our parent dies.
    CHECK(prctl(PR_SET_PDEATHSIG, SIGHUP) == 0);

    CHECK(ptrace(PTRACE_TRACEME) == 0);
    CHECK(kill(getpid(), SIGSTOP) == 0);
    CHECK(execvp(argv[0], argv) == 0);
  } else {
    capture(info, child);
  }
}

static void attach(const muxd_info* const info, const pid_t pid) {
  CHECK(ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == 0);
  capture(info, pid);
  CHECK(ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == 0);
}

static void mkdirp(const char* dir) {
  char tmp[PATH_MAX];
  char* p = nullptr;
  size_t len = strlen(tmp);

  snprintf(tmp, sizeof(tmp), "%s", dir);
  if (tmp[len - 1] == '/') tmp[len - 1] = 0;
  for (p = tmp + 1; *p; ++p) {
    if (*p == '/') {
      *p = 0;
      mkdir(tmp, S_IRWXU);
      *p = '/';
    }
  }
  mkdir(tmp, S_IRWXU);
}

static void fix_utc_zone() {
  static const unsigned char utc[] = {
      0x54, 0x5a, 0x69, 0x66, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x55, 0x54, 0x43, 0x00, 0x00, 0x00, 0x54, 0x5a, 0x69, 0x66,
      0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x54,
      0x43, 0x00, 0x00, 0x00, 0x0a, 0x55, 0x54, 0x43, 0x30, 0x0a};
  static const char* const path = "/usr/share/zoneinfo/UTC";
  if (access(path, F_OK) == -1) {
    mkdirp("/usr/share/zoneinfo/");
    const int fd = open(path, O_WRONLY | O_CREAT);
    CHECK(fd != -1);
    CHECK(write(fd, utc, sizeof(utc)) == sizeof(utc));
    CHECK(close(fd) == 0);
  }
}

EXPORT void muxd_info_init(muxd_info* const info) {
  memset(info, 0, sizeof(*info));
  info->output_fd = 1;
  info->output_directory = kDefaultOutputDir;
  info->file_regex = kDefaultFileRegex;
  info->filename_format = kDefaultFilenameFormat;
  info->line_format = kDefaultLineFormat;
  info->time_zone = kDefaultTimeZone;
}

EXPORT void muxd_run(const muxd_info* const info) {
  CHECK(info->output_directory);
  CHECK(info->file_regex && *info->file_regex);
  mkdirp(info->output_directory);
  if (!info->no_zoneinfo_fix) {
    fix_utc_zone();
  }
  std::vector<std::thread> threads;
  if (info->child_argv && *info->child_argv) {
    threads.push_back(std::thread(&spawn, info, info->child_argv));
  }
  for (size_t i = 0; i < info->pid_count; ++i) {
    const pid_t pid = info->pids[i];
    if (pid >= 0) {
      threads.push_back(std::thread(&attach, info, info->pids[i]));
    } else {
      std::vector<pid_t> tree_pids;
      enumerate(-pid, tree_pids);
      for (pid_t tree_pid : tree_pids) {
        threads.push_back(std::thread(&attach, info, tree_pid));
      }
    }
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
}