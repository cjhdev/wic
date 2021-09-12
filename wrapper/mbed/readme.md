MBED WIC Wrapper
================

This is a work in progress.

- TLS doesn't seem to connect
- interfaces need some work, especially around correct nsapi_error_t codes

## WIC::Client

A wrapper for client mode.

- TX, RX, and URL buffer sizes defined by template
- blocking interfaces that behave like the regular socket classes
- TCP or TLS mode determined by URL
- no need to create/destroy for each connection

An example:

~~~ c++
#include "wic_client.h"
#include "EthernetInterface.h"

int main()
{
    enum wic_encoding encoding;
    bool fin;
    static char buffer[1024];
    nsapi_size_or_error_t bytes;

    static EthernetInterface eth;
    static WIC::Client<sizeof(buffer)> client(eth);

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

There is one configuration item called `wic.mss`. By default this is
set equal to `lwip.tcp-mss`. The WIC wrapper uses this value
to ensure that no more than one segment of data is written to `send()`
at a time. Writing more than one segment will cause LWIP to perform
IP fragmentation.

## WIC::Server

No support for this mode at this time.

## Installation

Clone the WIC repository into a directory in your MBED project.
The `.mbedignore` file is written in such a way that the right sources
will be found by the build system.

## License

MIT

