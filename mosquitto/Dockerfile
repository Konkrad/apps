ARG BUILD_FROM
FROM $BUILD_FROM

# Install mosquitto + auth plugin
WORKDIR /usr/src
ARG LIBWEBSOCKET_VERSION
ARG MOSQUITTO_VERSION
COPY patches/0001-Fix-builtin-websockets-dropping-the-session-on-an-empty-data-frame.patch /usr/src
COPY plugin /usr/src/ha-auth
RUN apt-get update \
    && apt-get install -qy --no-install-recommends \
        pwgen \
        build-essential \
        cmake \
        git \
        openssl \
        patch \
        libssl-dev \
        libc-ares2 \
        libc-ares-dev \
        libcjson1 \
        libcjson-dev \
        libcurl4t64 \
        libcurl4-openssl-dev \
        libsqlite3-dev \
        xsltproc \
        docbook-xsl \
    \
    # Compile and install libwebsocket
    #
    # DLWS_WITHOUT_TESTAPPS is just a workaround, see
    # https://github.com/warmcat/libwebsockets/issues/2790 for more
    && git clone --depth 1 -b "v${LIBWEBSOCKET_VERSION}" \
       https://github.com/warmcat/libwebsockets \
    \
    && cd libwebsockets \
    && mkdir build \
    && cd build \
    && cmake -DLWS_WITH_EXTERNAL_POLL=ON -DLWS_WITHOUT_TESTAPPS=ON .. \
    && make install \
    && ldconfig \
    && cd ../.. \
    # Compile and install mosquitto
    && git clone --depth 1 -b "v${MOSQUITTO_VERSION}" \
       https://github.com/eclipse/mosquitto \
    \
    && cd mosquitto \
    && patch -p1 < /usr/src/0001-Fix-builtin-websockets-dropping-the-session-on-an-empty-data-frame.patch \
    # Disable editline used by mosquitto_ctrl
    && sed -i 's/^WITH_EDITLINE=yes/#WITH_EDITLINE=yes/' config.mk \
    # Disable REST API
    && sed -i 's/^WITH_HTTP_API=yes/#WITH_HTTP_API=yes/' config.mk \
    && make WITH_WEBSOCKETS=yes WITH_SRV=yes \
    && make install \
    && cd .. \
    # Compile and install the authentication plugin
    && make -C ha-auth install \
    \
    && apt-get purge -y --auto-remove \
        build-essential \
        git \
        patch \
        cmake \
        libssl-dev \
        libc-ares-dev \
        libcjson-dev \
        libcurl4-openssl-dev \
        libsqlite3-dev \
        xsltproc \
        docbook-xsl \
    && apt-get clean \
    && rm -fr \
        /etc/logrotate.d \
        /etc/mosquitto/* \
        /usr/src/libwebsockets \
        /usr/src/mosquitto \
        /usr/src/ha-auth \
        /usr/src/*.patch \
        /var/lib/apt/lists/* \
	/root/.cache

# Copy rootfs
COPY rootfs /

WORKDIR /
