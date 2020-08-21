MBED WIC Wrapper
================

This isn't working properly yet.

## WIC::Client

A wrapper for client mode.

- TX, RX, and URL buffer sizes defined by template
- blocking interfaces that behave like the regular socket classes
- TCP or TLS mode determined by URL
- no need to create/destroy for each connection

An example:

~~~ c++
#include "wic_client.hpp"
#include "EthernetInterface.h"

int main()
{
    enum wic_encoding encoding;
    bool fin;
    static char buffer[1000];
    nsapi_size_or_error_t bytes;

    static EthernetInterface eth;
    static WIC::Client<1000, 1012> client(eth);

    eth.connect();

    client.connect("ws://echo.websocket.org/");

    client.send("hello world!");

    bytes = client.recv(encoding, fin, buffer, 100);

    if((bytes >= 0) && (encoding == WIC_ENCODING_UTF8)){

        printf("got: %.*s\n", bytes, buffer);
    }
            
    client.close();                
}
~~~

## WIC::Server

No support for this mode at this time.

## Installation

Clone the WIC repository into a directory in your MBED project.
The `.mbedignore` file is written in such a way that the right sources
will be found by the build system.

## License

MIT

