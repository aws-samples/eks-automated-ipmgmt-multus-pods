# syntax=docker/dockerfile:1
FROM public.ecr.aws/amazonlinux/amazonlinux:latest
WORKDIR /app
RUN yum -y install python3 python3-pip
RUN yum -y install iproute
COPY requirements.txt requirements.txt
COPY script.sh script.sh
COPY assign-ip-new-ip6-parallel.py assign-ip-new-ip6-parallel.py
RUN pip3 install  -r requirements.txt
RUN chmod 755 /app/script.sh
