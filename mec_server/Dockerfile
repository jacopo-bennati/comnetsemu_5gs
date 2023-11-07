# Usa un'immagine basata su Debian con Python preinstallato
FROM python:3.9-slim-buster

# Install Bash
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        apt-utils \
        libsctp-dev \
        lksctp-tools \
        ethtool \
        iputils-ping \
        iproute2 \
        iptables \
        ifupdown \
        net-tools \
        curl \
        tcpdump \
        iperf3 && \
    apt-get autoremove -y && apt-get autoclean
