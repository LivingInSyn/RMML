# This is a dirty dockerfile for testing CI, feel free to ignore
# that it exists
from ubuntu:latest

run apt update
run apt install python3 python3-pip python-is-python3 -y
run pip3 install -U poetry

COPY . /app
WORKDIR /app
