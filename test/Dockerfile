FROM ubuntu:19.10@sha256:bd5f4f235eb31768b2c5caf1988bbdc182d4fc3cb6ee4aca6c6d74613f256140

COPY ./build/muxd /bin/muxd

CMD muxd -- echo "hello" || cat /tmp/*