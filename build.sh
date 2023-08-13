#!/bin/sh
chmod +x scripts/kill_timeout.sh
sudo whoami
# Be careful! May kill innocent processes!
sudo ./scripts/kill_timeout.sh &
docker image build --force-rm -t statefuzz_release:latest .
docker run --name statefuzz--container --privileged --rm  -it statefuzz_release:latest