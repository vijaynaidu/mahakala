FROM ubuntu:23.04
RUN apt-get update -y && apt-get install iptables -y

RUN apt-get install -y python3 && apt-get install python3-pip -y && apt-get install python3-venv -y

RUN mkdir -p /omts/mahakala
WORKDIR /omts/mahakala

CMD bash