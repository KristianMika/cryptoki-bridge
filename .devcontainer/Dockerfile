FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PROTOC_VERSION="24.2"

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# install requirements
RUN apt-get update && apt-get install --assume-yes \
    build-essential \
    git \
    clang \
    pkg-config \
    libssl-dev \
    curl \
    unzip

# install protoc
RUN curl -OL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" && \
    unzip -o "./protoc-${PROTOC_VERSION}-linux-x86_64.zip" -d ./proto && \
    chmod 755 -R ./proto/bin && \
    cp ./proto/bin/protoc /usr/bin/ && \
    protoc --version

# cleanup
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# set up user
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --shell /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME

USER dev

# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    echo 'source $HOME/.cargo/env' >> $HOME/.bashrc 
