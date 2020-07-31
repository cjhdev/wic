MBED WIC Wrapper
================

This example makes it a breeze to use WIC on MBED.

## WICClient

This is a wrapper class for client mode.

- supports TCP and TLS modes (determined by target URL)
- supports redirects (with configurable maximum number of redirects)
- blocking interfaces which must be called from a non-interrupt
  context
- handles full-duplex socket 'backpressure'

WICClient makes use of a number of synchronisation features in
order to work reliably in a multithreaded MBED application. These
include:

- dedicated threads for reading and writing
- mailboxes for incoming and outgoing messages/fragments
- event loop for serialising access to wic_inst and managing timing
- mutex and condition variable on application facing interfaces to
  implement blocking

The application below will try to connect every 10 seconds. Once connected, it will
send "hello world!" every 5 seconds. If the connection fails, it will return
to trying to open the connection.

~~~ c++
#include "wic_client.hpp"
#include "EthernetInterface.h"

int main()
{
    static EthernetInterface eth;

    eth.connect();

    static WICClient client(eth);

    for(;;){

        if(client.open("ws://echo.websocket.org/")){

            while(client.is_open()){

                client.text("hello world!");
                wait_us(5000);
            }        
        }
        else{

            wait_us(10000);
        }
    }
}
~~~

## WICServer

No support for this mode at this time.

## Installation

Clone the WIC repository into a directory in your MBED project.
The `.mbed-ignore` file is written in such a way that the right sources
will be found by the build system.

## License

MIT

