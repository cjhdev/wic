Websockets in C
===============

WIC is a C99 implementation of [rfc6455](https://tools.ietf.org/html/rfc6455)
websockets designed for embedded applications.

WIC decouples the protocol details from the transport layer. This makes
it possible to use WIC over any transport layer assuming you are prepared
to do the integration work. 

WIC is meant to support server and client roles, but at the moment
only supports client roles. Call it a work in progress.

## Features

- client role (server is todo)
- doesn't use malloc
- handshake header fields passed through to application
- convenience functions for dissecting URLs
- convenience functions for implementing redirection
- works with any transport layer you like
- automatic payload fragmentation on receive
- trivial to integrate with an existing build system

## Limitations

- interfaces are not thread-safe (provide your own solution)
- handshake headers are only accessible at the moment a websocket
  becomes connected (i.e. wic_get_state() == WIC_STATE_READY)
- doesn't support extensions
- doesn't directly support proxies
- doesn't automatically fragment the payload of outgoing messages

The handshake field limitation is a consequence of storing header
fields in the same buffer as used for receiving websocket frames. Applications
that require header fields to persist beyond WIC_STATE_READY will need
to copy the fields when they are available.

## Compiling

- add `include` to the search path
- compile sources in `src`

There are some macros you can define. These are commented in [include/wic.h](include/wic.h).

The WIC_PORT_HEADER macro can be used to define a filename which the
will include into wic.h. This might be the most
convenient place to define/redefine other macros.

## Usage

Below is an example of a client that:

- connects (after redirect if required)
- prints handshake headers
- sends a "hello world" text
- closes normally

~~~ c
#include "wic.h"

int main(int argc, char **argv)
{
    bool open;
    int s, redirects = 3;
    static uint8_t tx[1000], rx[1000];
    static char url[1000] = "ws://demos.kaazing.com/echo";
    struct wic_inst inst;
    struct wic_init_arg arg = {0};
    
    arg.tx = tx; arg.tx_max = sizeof(tx);    
    arg.rx = rx; arg.rx_max = sizeof(rx);    
    arg.write = do_write;
    arg.on_text = on_text_handler;        
    arg.on_open = on_open_handler;        
    arg.on_close = on_close_handler;        
    arg.app = &s;
    arg.url = url;
    arg.role = WIC_ROLE_CLIENT;

    for(;;){

        if(!wic_init(&inst, &arg)){

            exit(EXIT_FAILURE);
        };

        struct wic_header user_agent = {
            .name = "User-Agent",
            .value = "wic"
        };

        (void)wic_set_header(&inst, &user_agent);

        open = transport_open_client(
            wic_get_url_schema(&inst),
            wic_get_url_hostname(&inst),
            wic_get_url_port(&inst),
            &s
        );

        if(open){

            (void)wic_start(&inst);

            while(transport_recv(s, &inst));
        }

        wic_close(&inst);

        if(wic_get_redirect_url(&inst) && redirects){

            redirects--;
            strcpy(url, wic_get_redirect_url(&inst));
        }
        else{

            break;
        }
    }
    
    exit(EXIT_SUCCESS);
}

static void on_text_handler(struct wic_inst *inst, bool fin, const char *data, uint16_t size)
{
    printf("received text: %*.s\n", size, data);
}

static void on_open_handler(struct wic_inst *inst)
{
    const char *name, *value;

    printf("received handshake:\n");

    for(value = wic_get_next_header(inst, &name); value; value = wic_get_next_header(inst, &name)){

        printf("%s: %s\n", name, value);
    }

    const char msg[] = "hello world";

    wic_send_text(inst, true, msg, strlen(msg));
    wic_close(inst);
} 

static void on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size)
{
    transport_close((int *)wic_get_app(inst));
}
~~~

## Acknowledgements

WIC integrates code from the following projects:

- Joyent/Node-JS http-parser
- Bjoern Hoehrmann's UTF8 parser
- MBED TLS SHA1

All projects have permissive licenses. License notices for all can
be found in the source.

The Autobahn Test Suite has been used for verification.





