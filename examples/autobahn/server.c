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
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

static void on_close(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);
static void on_text(struct wic_inst *inst,  bool fin, const char *data, uint16_t size);
static void on_binary(struct wic_inst *inst, bool fin, const void *data, uint16_t size);
static void on_open(struct wic_inst *inst);
static void do_write(struct wic_inst *inst, const void *data, size_t size);
static uint32_t do_random(struct wic_inst *inst);

int main(int argc, char **argv)
{
    static struct wic_inst inst;
    static uint8_t tx[UINT16_MAX+10UL];
    static uint8_t rx[UINT16_MAX];
    
    srand(time(NULL));

    int server = -1;
    int client = -1;

    struct wic_init_arg arg = {0};

    arg.rx = rx;
    arg.rx_max = sizeof(rx);
    arg.tx = tx;
    arg.tx_max = sizeof(tx);
    arg.on_open = on_open;    
    arg.on_close = on_close;
    arg.on_text = on_text;
    arg.on_binary = on_binary;
    arg.write = do_write;
    arg.rand = do_random;
    arg.role = WIC_ROLE_SERVER;

    struct sockaddr_in serv_addr;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    
    server = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    if(server < 0){

        ERROR("socket()")
        exit(EXIT_FAILURE);            
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(9002);

    if(bind(server, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){

        ERROR("bind()")
        exit(EXIT_FAILURE);
    }

    for(;;){

        listen(server, 2);

        client = accept(server, (struct sockaddr *)&client_addr, &client_len);

        if(client < 0){

            ERROR("accept()")
            break;
        }

        arg.app = &client;

        if(!wic_init(&inst, &arg)){

            ERROR("wic_init()")
            transport_close(&client);
            break;
        }
        
        while(transport_recv(client, &inst));
        
        wic_close(&inst);
    }

    transport_close(&server);

    LOG("exiting...")

    exit(EXIT_SUCCESS);
}

static void on_close(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size)
{
    transport_close((int *)wic_get_app(inst));    
}

static void on_text(struct wic_inst *inst, bool fin, const char *data, uint16_t size)
{
    wic_send_text(inst, fin, data, size);
}

static void on_binary(struct wic_inst *inst,  bool fin, const void *data, uint16_t size)
{
    wic_send_binary(inst, fin, data, size);
}

static void on_open(struct wic_inst *inst)
{
    wic_start(inst);
}

static void do_write(struct wic_inst *inst, const void *data, size_t size)
{
    if(!transport_write(*(int *)wic_get_app(inst), data, size)){

        ERROR("transport_write()")

        wic_close(inst);
    }
}

static uint32_t do_random(struct wic_inst *inst)
{
    return rand();
}
