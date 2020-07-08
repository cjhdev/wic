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

#include "transport.h"
#include "log.h"
#include "wic.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

bool transport_open_client(const char *schema, const char *host, uint16_t port, int *s)
{
    char pbuf[20];
    struct addrinfo *res;
    bool retval = false;
    const char *service = NULL;
    int tmp;

    printf("%s\n", host);

    (void)memset(pbuf, 0, sizeof(pbuf));

    if(
        (strcmp("https", schema) == 0)
        ||
        (strcmp("wss", schema) == 0)
    ){
        ERROR("not supporting https or wss schemas at the moment")
        return false;
    }

    if(port != 0){
    
        (void)snprintf(pbuf, sizeof(pbuf), "%u", port);
        service = pbuf;        
    }
    else{

        service = "80";
    }

    tmp = getaddrinfo(host, service, NULL, &res);

    if(tmp != 0){

        ERROR("getaddrinfo() %s", gai_strerror(tmp));    
    }
    else{

        *s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

        if(*s < 0){

            ERROR("socket() errno %d", errno);
        }
        else{

#if 0
            {
                int val = 1;
                (void)setsockopt(*s, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
            }
#endif            

            if(connect(*s, res->ai_addr, res->ai_addrlen) < 0){

                ERROR("connect() errno %d", errno)
                close(*s);
            }
            else{

                LOG("connected!");
                retval = true;
            }
        }

        freeaddrinfo(res);
    }

    return retval;
}

bool transport_write(int s, const void *data, size_t size)
{
    return (write(s, data, size) == size);
}

bool transport_recv(int s, struct wic_inst *inst)
{
    static uint8_t buffer[1000U];
    ssize_t bytes;
    
    bytes = recv(s, buffer, sizeof(buffer), 0);

    if(bytes > 0){
        
        wic_parse(inst, buffer, bytes);
    }

    if(bytes < 0){

        ERROR("socket error")
    }

    if(bytes == 0){

        ERROR("socket closed")
    }

    return (bytes > 0);
}

void transport_close(int *s)
{
    if(*s > 0){
        close(*s);        
        *s = -1;
    }
}
