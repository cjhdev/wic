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

#include "wic_client.h"
#include "wic_nsapi.h"
#include "EthernetInterface.h"
#include <cinttypes>

Timer timer;

#define PUTS(...) do{\
    printf(__VA_ARGS__);\
    printf("\n");\
}while(0);

int i;

uint32_t time_since()
{
    timer.start();

    static uint32_t time = timer.read_us();

    uint32_t now = timer.read_us();
    uint32_t retval = now - time;
    time = now;

    return retval;
}
    
int main()
{
    enum wic_encoding encoding;
    bool fin;
    static char buffer[1000];
    nsapi_size_or_error_t retval;
    nsapi_size_or_error_t bytes;
    int n;

    static EthernetInterface eth;
    static WIC::Client<sizeof(buffer)> client(eth);

    eth.connect();

    retval = client.connect("ws://192.168.1.108:9001/getCaseCount?agent=mbed");

    if(retval == NSAPI_ERROR_OK){

        retval = client.recv(encoding, fin, buffer, sizeof(buffer));

        if(retval < 0){

            PUTS("failed to read number of test cases (%s)", WIC::nsapi_error_to_s(retval));        
        }
        else{

            buffer[retval] = 0;
            n = atoi(buffer);

            PUTS("preparing to run through %d test cases", n);
        
            client.close();

            for(int tc=1U; tc <= n; tc++){

                const char url_base[] = "ws://192.168.1.108:9001/";
                char url[100];
                snprintf(url, sizeof(url), "%srunCase?case=%d&agent=mbed", url_base, tc);

                PUTS("BEGIN TC%d", tc);

                retval = client.connect(url);

                if(retval == NSAPI_ERROR_OK){

                    for(;;){

                        retval = client.recv(encoding, fin, buffer, sizeof(buffer));

                        if(retval >= 0){

                            bytes = retval;

                            time_since();

                            retval = client.send(buffer, bytes, encoding, fin);

                            if(retval != bytes){

                                PUTS("tc%d: breaking loop after send() returned %s", tc, WIC::nsapi_error_to_s(retval));
                                break;
                            }
                        }
                        else{

                            PUTS("tc%d: breaking loop after recv() returned %s", tc, WIC::nsapi_error_to_s(retval));
                            break;
                        }
                    }

                    time_since();
                    
                    client.close();
                }
                else{

                    PUTS("tc%d: connect() failed with retval %s", tc, WIC::nsapi_error_to_s(retval));
                }

                PUTS("END TC%d", tc);
            }

            client.connect("ws://192.168.1.108:9001/updateReports?agent=mbed");        
        }

        client.close();

    }
    else{

        PUTS("connect() failed with retval %s", WIC::nsapi_error_to_s(retval));
    }

    PUTS("all done");
}
