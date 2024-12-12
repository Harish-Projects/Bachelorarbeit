FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
        build-essential \
        git \
        vim \
        libpcap-dev \
        curl \
        autoconf \
        m4 \
        automake \
        perl\
        net-tools

RUN mkdir /data
WORKDIR /data
COPY /data/Backdoor_attack.pcap . 

RUN mkdir /app
COPY tcpreplay-4.5.1.tar.xz /app
WORKDIR /app
RUN tar -xvf tcpreplay-4.5.1.tar.xz
WORKDIR /app/tcpreplay-4.5.1
RUN ./configure
RUN make
RUN make install

CMD ["sh", "-c", "tcpreplay -i eth0 -K --mbps 1 --loop 1 --unique-ip $pcap_file"]