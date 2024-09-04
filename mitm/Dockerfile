# Use an official Python runtime as a parent image
FROM python:3.9-slim

RUN apt-get update && \
    apt-get -y install git cmake make gcc g++

# Install necessary Python libraries
COPY requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt

# Install CryptoMobile Python library
RUN cd tmp && git clone https://github.com/mitshell/CryptoMobile.git && \
    cd CryptoMobile && python3 setup.py install

# Expose SCTP port
EXPOSE 38412
