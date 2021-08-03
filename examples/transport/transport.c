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

#ifdef WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#undef ssize_t
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
void transport_init() {
    WORD wVersionRequested; WSADATA wsaData;
    wVersionRequested = MAKEWORD(2, 2);
    WSAStartup(wVersionRequested, &wsaData);
}

#else

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

void transport_init() {}

#endif

#include <string.h>
#include "transport.h"
#include "log.h"

bool transport_open_client(enum wic_schema schema, const char *host, uint16_t port, int *s)
{
    transport_init();

    char pbuf[20];
    struct addrinfo *res;
    bool retval = false;
    const char *service = NULL;
    int tmp;

    (void)memset(pbuf, 0, sizeof(pbuf));

    switch(schema){
    case WIC_SCHEMA_HTTPS:
    case WIC_SCHEMA_WSS:

        ERROR("not supporting https or wss schemas at the moment")
        return false;

    default:
        break;
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

                retval = true;
            }
        }

        freeaddrinfo(res);
    }

    return retval;
}

void transport_write(int s, const void *data, size_t size)
{
    const uint8_t *ptr = data;
    size_t pos;
    int retval;

    for(pos=0U; pos < size; pos += retval){

#ifdef WIN32
        retval = send(s, &ptr[pos], size - pos, 0);
#else
        retval = write(s, &ptr[pos], size - pos);
#endif
        
        if(retval <= 0){

            break;
        }
    }
}

bool transport_recv(int s, struct wic_inst *inst)
{
    static uint8_t buffer[1000U];
    ssize_t bytes;
    size_t retval, pos;

    bytes = recv(s, buffer, sizeof(buffer), 0);

    if(bytes > 0){

        for(pos=0U; pos < bytes; pos += retval){
        
            retval = wic_parse(inst, &buffer[pos], bytes - pos);
        }
    }
    
    if(bytes <= 0){

        wic_close_with_reason(inst, WIC_CLOSE_ABNORMAL_2, NULL, 0);
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
