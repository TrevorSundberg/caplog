# muxd
```
Capture stdout/stderr from multiple processes and mux or demux them
e.g. muxd --outdir=/tmp --pids=1,2,-3 -- ping google.com
Usage:
  muxd [OPTION...] positional parameters

  -p, --pids arg             The pid or list of pids to capture from (use
                             negative to capture the entire process group). e.g.
                             --pids=1,2,-3
  -o, --outdir arg           The directory where all logs will be written to.
                             e.g. --outdir="/tmp" (default)
  -r, --file-regex arg       Test a regex against a full file path to see if
                             it should be included in the output (stdout and
                             stderr are special keywords). e.g.
                             --file-regex="stdout|stderr" (default)
  -f, --filename-format arg  Timestampped format for the filename of a log.
                             See http://bit.ly/date-format for details. You can
                             also use %P for process name, %i for pid, and %f
                             for original filename e.g.
                             --filename-format="%P:%i_%f_%F_%T_%z.log" (default)
  -l, --line-format arg      Timestampped format for each line in a log. See
                             http://bit.ly/date-format for details. You can
                             also use %P for process name, %i for pid, %f for
                             original filename, and %l for the line text. If
                             left empty, the contents will be written unmodified
                             e.g. --line-format="[%F %T %z] %l%n" (default)
  -z, --time-zone arg        Time zone that we print all dates in. See
                             http://www.iana.org/time-zones for details. If set to
                             empty "", the local time zone is used. e.g.
                             --time-zone="UTC" (default)
  -h, --help                 Print usage
```
