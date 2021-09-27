#include "wic_plus.h"

#include <cstdlib>

int main(int argc, char **argv)
{
    WIC::Client client;

    client.connect("ws://echo.websocket.org/");

    //client.send_utf8("hello world");

#if 0
    client.on_recv(
        [](){

            client.recv(&buffer)
        }
    );
#endif

    exit(EXIT_SUCCESS);
}
