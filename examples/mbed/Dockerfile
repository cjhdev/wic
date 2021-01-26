FROM debian:9

# copy in the requirements file from the already checked out mbed-os
#
# this will be used to dowload all the missing python stuff
COPY mbed-os/requirements.txt /tmp/mbed-cli-deps/requirements.txt

RUN dpkg --add-architecture i386 \
  && DEBIAN_FRONTEND=noninteractive apt-get update -y -q \
  && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    python python-pip \
    libc6:i386 libncurses5:i386 libstdc++6:i386 \
    crossbuild-essential-armhf build-essential git mercurial \
    wget \
  && pip install mbed-cli \
  && pip install -r /tmp/mbed-cli-deps/requirements.txt

ARG toolchain_name
ARG toolchain_url

# get the toolchain
RUN cd /opt && wget $toolchain_url -O - | tar xj

ENV GCC_ARM_PATH /opt/toolchain/bin
ENV PATH="/opt/$toolchain_name/bin:${PATH}"

RUN mbed config --global toolchain GCC_ARM

WORKDIR /mbed
VOLUME /mbed

ENTRYPOINT [ "mbed" ]
