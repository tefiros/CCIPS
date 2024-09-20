FROM ubuntu:18.04
RUN \
      apt-get update && apt-get install -y \
      # general tools
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      # libyang
      libpcre3-dev \
      pkg-config \
      # sysrepo
      libavl-dev \
      libev-dev \
      libprotobuf-c-dev \
      protobuf-c-compiler \
      # netopeer2 \
      libssh-dev \
      libssl-dev \
      # bindings
      swig \
      python-dev

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# libyang
RUN \
      git clone --branch v1.0-r5 https://github.com/CESNET/libyang.git && \
      cd libyang && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# sysrepo
RUN \
      git clone --branch v0.7.9 https://github.com/sysrepo/sysrepo.git && \
      cd sysrepo && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo .. && \
      make -j2 && \
      make install && \
      ldconfig

# libnetconf2
RUN \
      git clone --branch v0.12-r2 https://github.com/CESNET/libnetconf2.git && \
      cd libnetconf2 && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# keystore
RUN \
      cd /opt/dev && \
      git clone --branch v0.7-r2 https://github.com/CESNET/Netopeer2.git && \
      cd Netopeer2 && \
      cd keystored && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      ldconfig

# netopeer2
RUN \
      cd /opt/dev && \
      cd Netopeer2/server && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      cd ../../cli && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install


WORKDIR /
RUN apt update && apt-get install ipsec-tools build-essential libpam0g-dev wget strongswan-swanctl -y 
RUN wget https://download.strongswan.org/strongswan-5.7.0.tar.bz2 && bunzip2 strongswan-5.7.0.tar.bz2 && tar -xvf strongswan-5.7.0.tar 
RUN cd strongswan-5.7.0 && \
 ./configure  --enable-eap-identity --enable-eap-md5 --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap --enable-xauth-pam --enable-dhcp --enable-openssl --enable-addrblock --enable-unity --enable-certexpire --enable-radattr --enable-swanctl --disable-gmp && \
 make && make install

# Tools for debugging
RUN apt update && apt install iputils-ping iproute2 tcpdump curl libpam0g-dev autotools-dev autoconf -y 

RUN ln -s /strongswan-5.7.0/src/libcharon/plugins/vici/libvici.h /usr/local/include/libvici.h
RUN ln -s /strongswan-5.7.0/src/libcharon/plugins/vici/libvici.h /usr/lib/libvici.h
RUN ln -s /strongswan-5.7.0/src/libcharon/plugins/vici/.libs/libvici.so /usr/lib/.
RUN ln -s /strongswan-5.7.0/src/libcharon/plugins/vici/.libs/libvici.o /usr/lib/.
RUN echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"' >> /etc/environment
RUN echo 'LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib/ipsec"' >> /etc/environment
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/ipsec
COPY cne-cfgipsec2 /cne-cfgipsec2
WORKDIR /cne-cfgipsec2
RUN chmod +x /cne-cfgipsec2/configure 
RUN ./configure 
RUN cp ietf-ipsec.yang /ietf-ipsec.yang
RUN make  && make install
WORKDIR /

# Setup netconf user
RUN adduser --system netconf
RUN mkdir -p /home/netconf/.ssh
RUN echo "netconf:netconf" | chpasswd && adduser netconf sudo;

# Enable ip-forwarding
RUN sysctl net.ipv4.conf.all.forwarding=1



COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]