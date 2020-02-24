// MIT License, copyright Trevor Sundberg 2020 (see LICENSE)
#pragma once

struct muxd_info {
  char** child_argv;
  const int* pids;
  int pid_count;
  int output_fd;
  const char* output_directory;
  const char* file_regex;
  const char* filename_format;
  const char* line_format;
  const char* time_zone;
};

#ifdef __cplusplus
extern "C" {
#endif

void muxd_info_init(muxd_info* info);
void muxd_run(const muxd_info* info);

#ifdef __cplusplus
}  // extern "C"
#endif
