/* Copyright (c) 2023 Cameron Harper
 *
 * */

#include "log.h"

#include <string.h>
#include <signal.h>
#include <time.h>

#include "wic_plus.h"
#include <stdlib.h>

bool log_enabled = false;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    static int n = 0;

    WIC::Client client;

    uint8_t rx_buffer[UINT16_MAX];

    char url[100];

    wic_encoding encoding;
    bool fin;
    size_t size;

    if(client.connect("ws://localhost:9001/getCaseCount?agent=wic") != WIC_STATUS_SUCCESS){

    }
    else if(client.recv(encoding, fin, rx_buffer, sizeof(rx_buffer), size) != WIC_STATUS_SUCCESS){

        WIC_ERROR("main", "cannot recv")
    }
    else{

        LOG("%.*s", (int)size, rx_buffer);

        if(size > 0){

            n = atoi((char *)rx_buffer);
        }

        client.close();

        for(int tc=1; tc <= n; tc++){

            snprintf(url, sizeof(url), "ws://localhost:9001/runCase?case=%d&agent=wic", tc);

            LOG("test #%d...", tc)

            if(client.connect(url) != WIC_STATUS_SUCCESS){


            }
            else{

                do{

                    auto status = client.recv(encoding, fin, rx_buffer, sizeof(rx_buffer), size);

                    switch(status){
                    default:
                        break;

                    case WIC_STATUS_SUCCESS:

                        LOG("received %u bytes of %s %s", (unsigned)size, (encoding == WIC_ENCODING_UTF8) ? "text" : "binary", fin ? "(final)" : "");
                        break;
                    }
                }
                while(true);
            }
        }

        if(client.connect("ws://localhost:9001/updateReports?agent=wic") != WIC_STATUS_SUCCESS){

        }
        else{

            client.close();
        }
    }

    LOG("exiting...")

    exit(EXIT_SUCCESS);
}

