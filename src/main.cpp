// MIT License, copyright Trevor Sundberg 2020 (see LICENSE)
#include <iostream>
#include <vector>

#include <cxxopts.hpp>

#include "muxd.h"

int main(int argc, char* argv[]) {
  cxxopts::Options options(
      "muxd",
      "Capture stdout/stderr from multiple processes\ne.g. muxd --outdir=/tmp "
      "--pids=1,2,-3 -- ping google.com");

  muxd_info info;
  muxd_info_init(&info);

  auto add = options.add_options();
  std::vector<std::string> child;
  add("c,child",
      "Execute the child capture from it and all of its children. e.g. "
      "muxd -- ping google.com",
      cxxopts::value<decltype(child)>(child));
  options.parse_positional({"child"});

  std::vector<pid_t> pids;
  add("p,pids",
      "The pid or list of pids to capture from (use negative "
      "to capture the entire process group). e.g. --pids=1,2,-3",
      cxxopts::value<decltype(pids)>(pids));

  std::string output_directory = info.output_directory;
  add("o,outdir",
      "The directory where all logs will be written to. e.g. --outdir=\"" +
          output_directory + "\" (default)",
      cxxopts::value<decltype(output_directory)>(output_directory));

  std::string file_regex = info.file_regex;
  add("r,file-regex",
      "Test a regex against a full file path to see if it should be included "
      "in the output (stdout and stderr are special keywords). e.g. "
      "--file-regex=\"" +
          file_regex + "\" (default)",
      cxxopts::value<decltype(file_regex)>(file_regex));

  std::string filename_format = info.filename_format;
  add("f,filename-format",
      "Timestampped format for the filename of a log. See "
      "http://bit.ly/date-format for details. You can also use %P for process "
      "name, %i for pid, and %f for original filename e.g. "
      "--filename-format=\"" +
          filename_format + "\" (default)",
      cxxopts::value<decltype(filename_format)>(filename_format));

  std::string line_format = info.line_format;
  add("l,line-format",
      "Timestampped format for each line in a log. See "
      "http://bit.ly/date-format for details. You can also use %P for process "
      "name, %i for pid, %f for original filename, and %l for the line text. "
      "If left empty, the contents will be written unmodified e.g. "
      "--line-format=\"" +
          line_format + "\" (default)",
      cxxopts::value<decltype(line_format)>(line_format));

  std::string time_zone = info.time_zone;
  add("z,time-zone",
      "Time zone that we print all dates in. See "
      "http://www.iana.org/time-zones for details. If set to empty \"\", the "
      "local time zone is used. e.g. --time-zone=\"" +
          time_zone + "\" (default)",
      cxxopts::value<decltype(time_zone)>(time_zone));

  add("h,help", "Print usage");

  auto result = options.parse(argc, argv);

  if (result.count("help")) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  std::vector<char*> child_argv;
  child_argv.reserve(child.size());
  for (auto& str : child) {
    child_argv.push_back((char*)str.data());
  }
  child_argv.push_back(nullptr);

  info.pids = pids.data();
  info.pid_count = (int)pids.size();
  info.child_argv = child_argv.data();
  info.output_directory = output_directory.c_str();
  info.file_regex = file_regex.c_str();
  info.filename_format = filename_format.c_str();
  info.line_format = line_format.c_str();

  muxd_run(&info);
  return 0;
}