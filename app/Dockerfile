FROM ubuntu:24.04
RUN apt update
RUN apt install -y \
    build-essential \
    sudo \
    checkinstall \
    zlib1g-dev \
    wget \
    cmake \
    gcc \
    ninja-build \
    libssl-dev \
    doxygen \
    valgrind \
    git \
    autoconf \
    automake \
    libpcre2-dev \
    python3.12 \
    python3.12-venv \
    python3.12-dev \
    python3-pip


RUN mkdir $HOME/PQ-NEXT

RUN cd $HOME/PQ-NEXT && wget https://www.openssl.org/source/openssl-3.6.0.tar.gz && \
    tar -xvzf openssl-3.6.0.tar.gz && \
    cd openssl-3.6.0 && \
    ./config && \
    make && \
    sudo make install

RUN rm /usr/lib/x86_64-linux-gnu/libssl.so && \
    rm /usr/lib/x86_64-linux-gnu/libcrypto.so && \
    rm /usr/lib/x86_64-linux-gnu/libssl.so.3 && \
    rm /usr/lib/x86_64-linux-gnu/libcrypto.so.3 && \
    ln -s /usr/local/lib64/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so && \
    ln -s /usr/local/lib64/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3 && \
    ln -s /usr/local/lib64/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so && \
    ln -s /usr/local/lib64/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3

# Añadir OpenSSL al PATH
RUN export PATH=/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin:$PATH
RUN export LD_LIBRARY_PATH=/usr/lib:/usr/local/lib:/usr/local/lib64:$LD_LIBRARY_PATH

RUN echo "export OPENSSL_CONF='/usr/local/ssl/openssl.cnf'"
RUN echo "export OPENSSL_MODULES='/usr/local/ssl/lib64/ossl-modules'"
RUN echo "export PATH='/usr/local/ssl/bin:$PATH'"


#Instalar liboqs-python
# RUN cd $HOME/PQ-NEXT && git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs-python.git
# ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
# ENV PYTHONPATH=$PYTHONPATH:/home/oqs/liboqs-python
# RUN cd $HOME/PQ-NEXT/liboqs-python && pip install . 


RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:$PATH"
WORKDIR /home/ubuntu/PQ-NEXT
RUN git clone --depth 1 --branch CCIPS-Python https://github.com/tefiros/CCIPS.git
RUN pip install --no-cache-dir \
    Flask==2.3.0 \
    requests==2.31.0 \
    flask \
    ncclient \
    pydantic \
    netconf-client

WORKDIR /home/ubuntu/PQ-NEXT/CCIPS-Python/app
EXPOSE 5000
ENTRYPOINT ["python3.12", "main.py"]