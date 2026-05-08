# Pinned libzmq for F4 interop. ZeroMQ 4.3.x is the LTS line.
# pyzmq prebuilt wheels bundle their own libzmq; --no-binary forces a
# source build that links against the pinned system libzmq5=4.3.4.

FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libzmq5=4.3.4-* \
        libzmq3-dev=4.3.4-* \
        pkg-config \
        gcc \
 && rm -rf /var/lib/apt/lists/*

# --no-binary pyzmq: build from source so pkg-config picks up system libzmq.
RUN pip install --no-cache-dir --no-binary pyzmq 'pyzmq==25.*'

WORKDIR /bridge
COPY bridge.py /bridge/bridge.py

ENTRYPOINT ["python3", "/bridge/bridge.py"]
