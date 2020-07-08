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

static void on_open_handler(struct wic_inst *inst);
static void on_text_handler(struct wic_inst *inst, bool fin, const char *data, uint16_t size);
static void on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);
static void do_write(struct wic_inst *inst, const void *data, size_t size);

int main(int argc, char **argv)
{
    bool open;
    int s, redirects = 3;
    static uint8_t tx[1000], rx[1000];
    static char url[1000] = "ws://echo.websocket.org/";
    struct wic_inst inst;
    struct wic_init_arg arg = {0};

    if(argc > 1){

        strcpy(url, argv[1]);
    }
    
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

static void do_write(struct wic_inst *inst, const void *data, size_t size)
{
    if(!transport_write(*(int *)wic_get_app(inst), data, size)){

        wic_close(inst);
    }
}
