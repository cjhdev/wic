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
