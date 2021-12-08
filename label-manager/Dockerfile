FROM python:3

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y tshark && \
    apt-get install -y libtool && \
    apt-get install -y tcpdump && \
    # binutils are necessary to use strip utility
    apt-get install -y --no-install-recommends binutils && \
    # this is required due to incompatibilities on Centos 7 hosts see issue #4 for details
    ldconfig -p | grep libQt5Core.so.5 | cut -d '>' -f 2 | xargs -I{} strip --remove-section=.note.ABI-tag {} && \
    apt-get remove -y --purge binutils && \
    apt-get autoremove -y --purge && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1
WORKDIR /code/tstat-3.1.1

# Install tstat library  
COPY tstat-3.1.1 . 

RUN cp /code/tstat-3.1.1/tstat/tstat /usr/local/sbin

WORKDIR /code

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /code/

RUN chmod a+x ./docker-entrypoint.sh
ENTRYPOINT ["./docker-entrypoint.sh"]