/* Copyright (c) 2020 Cameron Harper
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * */

#include "wic.h"
#include "transport.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <signal.h>

bool log_enabled = true;

static void on_open_handler(struct wic_inst *inst);
static bool on_message_handler(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size);
static void on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);
static void on_close_transport_handler(struct wic_inst *inst);
static void on_send_handler(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type);
static void on_handshake_failure_handler(struct wic_inst *inst, enum wic_handshake_failure reason);
static void *on_buffer_handler(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size);

int main(int argc, char **argv)
{
    int s, redirects = 3;
    static uint8_t rx[1000];
    static char url[1000] = "ws://echo.websocket.org/";
    struct wic_inst inst;
    struct wic_init_arg arg = {0};

    if(argc > 1){

        strcpy(url, argv[1]);
    }
    
    arg.rx = rx; arg.rx_max = sizeof(rx);    
    arg.on_send = on_send_handler;
    arg.on_buffer = on_buffer_handler;
    arg.on_message = on_message_handler;        
    arg.on_open = on_open_handler;        
    arg.on_close = on_close_handler;        
    arg.on_close_transport = on_close_transport_handler;        
    arg.on_handshake_failure = on_handshake_failure_handler;
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

        if(
            transport_open_client(
                wic_get_url_schema(&inst),
                wic_get_url_hostname(&inst),
                wic_get_url_port(&inst),
                &s
            )
        ){

            if(wic_start(&inst) == WIC_STATUS_SUCCESS){

                while(transport_recv(s, &inst));
            }
            else{

                transport_close(&s);
            }
        }

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

static bool on_message_handler(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size)
{
    if(encoding == WIC_ENCODING_UTF8){

        LOG("received text: %.*s", size, data);
    }

    wic_close(inst);

    return true;
}

static void on_handshake_failure_handler(struct wic_inst *inst, enum wic_handshake_failure reason)
{
    LOG("websocket handshake failed for reason %d", reason);
}

static void on_open_handler(struct wic_inst *inst)
{
    const char *name, *value;

    LOG("websocket is open");
    
    LOG("received handshake:");

    for(value = wic_get_next_header(inst, &name); value; value = wic_get_next_header(inst, &name)){

        LOG("%s: %s", name, value);
    }

    const char msg[] = "hello world";

    wic_send_text(inst, true, msg, strlen(msg));
} 

static void on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size)
{
    LOG("websocket closed for reason %u", code);
}

static void on_close_transport_handler(struct wic_inst *inst)
{
    transport_close((int *)wic_get_app(inst));
}

static void on_send_handler(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type)
{
    LOG("sending buffer type %d", type);

    transport_write(*(int *)wic_get_app(inst), data, size);
}

static void *on_buffer_handler(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size)
{
    static uint8_t tx[1000U];

    *max_size = sizeof(tx);

    return (min_size <= sizeof(tx)) ? tx : NULL;
}
