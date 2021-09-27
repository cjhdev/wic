WebSockets in C
===============

WIC is a C99 implementation of [rfc6455](https://tools.ietf.org/html/rfc6455)
websockets designed for embedded applications.

WIC is different to other websocket implementations in the way that it separates
the core implementation of the protocol from the transport layer and platform specific interfaces.
This means it is possible to port WIC to just about any target/application without needing to hack
the code.

## Features (WIC core)

- doesn't depend on malloc
- handshake header fields passed through to application
- convenience functions for dissecting URLs
- convenience functions for implementing redirection
- works with any transport layer you like
- automatic payload fragmentation on receive
- trivial to integrate with an existing build system

## Limitations (WIC core)

- interfaces are not thread-safe (provide your own solution)
- handshake headers are only accessible at the moment a websocket
  becomes connected (i.e. wic_get_state() == WIC_STATE_READY)
- doesn't support extensions
- there are a bewildering number of function pointers
- enums must be at least 16 bit

The handshake field limitation is a consequence of storing header
fields in the same buffer as used for receiving websocket frames. Applications
that require header fields to persist beyond WIC_STATE_READY will need
to copy the fields when they are available.

## Wrappers / Integrations

- [WIC++](wrapper/wic_plus): cross platform general purpose C++ wrapper making use of Asio
- [mbed](wrapper/mbed): websockets for MBED

## Compiling

- add `include` to the search path
- create empty file in search path and name it `wic_config.h`
- compile sources in `src`

`wic_config.h` can be empty, or it can contain definitions for:

- WIC_DEBUG(...): debug level log message
- WIC_ERROR(...): error level log message
- WIC_ASSERT(XX): assertions
- WIC_HOSTNAME_MAXLEN: redefine the maximum size of hostname buffer

## Examples

- [minimalistic single-thread client on sockets API (Linux)](examples/demo_client/main.c)
- [same as above but using WIC++](examples/wic_plus/main.cpp)
- [MBED client](examples/mbed/tcp_client)

## Acknowledgements

WIC integrates code from the following projects:

- Joyent/Node-JS http-parser
- Bjoern Hoehrmann's UTF8 parser
- MBED TLS SHA1 (modified to suit this project)
- C++ Asio (WIC++ wrapper)

The Autobahn Test Suite has been used for verification.





