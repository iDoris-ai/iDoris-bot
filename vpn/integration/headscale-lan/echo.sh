#!/bin/sh
# Non-Tailscale TCP echo used as the NAS / AI box behind the subnet router.
# Both ports answer; the ACL, not this process, decides which one a member sees.
set -eu
(while true; do nc -lk -p 8740 -e echo ok; done) >/dev/null 2>&1 &
while true; do nc -lk -p 8080 -e echo ok; done
