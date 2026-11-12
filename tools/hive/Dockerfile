# zesu Hive consume-rlp client
#
# Build stage: compile the hive-rlp binary
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget xz-utils ca-certificates git cmake make \
        libsecp256k1-dev libssl-dev \
        pkg-config gcc g++ clang libc++-dev libc++abi-dev libgmp-dev libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.16.0
ARG ZIG_VERSION=0.16.0
ARG TARGETARCH
RUN case "${TARGETARCH:-amd64}" in \
        amd64) ZIG_ARCH=x86_64 ;; \
        arm64) ZIG_ARCH=aarch64 ;; \
        *) ZIG_ARCH=x86_64 ;; \
    esac && \
    wget -q "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
    && tar xf "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
    && mv "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /usr/local/zig \
    && rm "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz"
ENV PATH="/usr/local/zig:${PATH}"

# Build blst from source → /usr/local/lib/libblst.a
RUN git clone --depth=1 https://github.com/supranational/blst.git /tmp/blst && \
    cd /tmp/blst && \
    ./build.sh && \
    cp libblst.a /usr/local/lib/libblst.a && \
    cp bindings/blst.h bindings/blst_aux.h /usr/local/include/ && \
    rm -rf /tmp/blst

# Build mcl from source → /usr/local/lib/libmcl.so (linked dynamically on Linux; see build.zig)
RUN git clone --depth=1 https://github.com/herumi/mcl.git /tmp/mcl && \
    cd /tmp/mcl && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS="-stdlib=libc++" && \
    make -j$(nproc) mcl && \
    cp lib/libmcl.so* /usr/local/lib/ && \
    ldconfig && \
    cp -r ../include/mcl /usr/local/include/ && \
    rm -rf /tmp/mcl

WORKDIR /src
COPY build.zig* ./
COPY src ./src
COPY tools ./tools

# Build the hive-rlp binary (ReleaseFast for container use)
RUN zig build hive-rlp -Doptimize=ReleaseFast

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libsecp256k1-dev libssl-dev libc++1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/libmcl.so* /usr/local/lib/
RUN ldconfig
COPY --from=build /src/zig-out/bin/hive-rlp /hive-rlp

EXPOSE 8545

ENTRYPOINT ["/hive-rlp"]
