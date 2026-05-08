# Pinned libzmq for F4 interop. ZeroMQ 4.3.x is the LTS line.
# pyzmq wheels for arm64/amd64 ship with their own embedded libzmq —
# we install libzmq via the distro package to keep one source of truth
# and force pyzmq to bind against it via PYZMQ_BACKEND=cython.

FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libzmq5=4.3.4-* \
        libzmq3-dev=4.3.4-* \
        pkg-config \
        gcc \
 && rm -rf /var/lib/apt/lists/*

# Build pyzmq against the system libzmq (not the bundled wheel).
ENV PYZMQ_BACKEND_CYTHON=1
RUN pip install --no-cache-dir 'pyzmq==25.*'

WORKDIR /bridge
COPY bridge.py /bridge/bridge.py

ENTRYPOINT ["python3", "/bridge/bridge.py"]
