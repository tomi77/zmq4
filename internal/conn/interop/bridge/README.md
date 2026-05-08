# F4 libzmq interop bridge

Used only by `internal/conn/interop/*_test.go` (build tag `interop`).
Not part of the production runtime.

The bridge is a Python (`pyzmq`) program that opens a single libzmq
`ZMQ_PAIR` socket per invocation. It is launched in a Docker container
(see `../Dockerfile`) by the Go fixture (`../fixture/fixture.go`).

Run-by-hand for debugging:

    docker build -t zmq4-interop-bridge -f ../Dockerfile ../bridge
    echo '{"role":"listener","endpoint":"tcp://*:5555","mechanism":"NULL","scenario":"handshake"}' \
        | docker run --rm -i --network=host zmq4-interop-bridge

Expected output:

    READY tcp://0.0.0.0:5555
    OK

The bridge accepts exactly one line of JSON on stdin (schema in
`bridge.py` docstring) and exits with status 0 on success.
