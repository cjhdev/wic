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

#include "wic_client.hpp"
#include "EthernetInterface.h"

int main()
{
    enum wic_encoding encoding;
    bool fin;
    static char buffer[1000];
    nsapi_size_or_error_t bytes;

    static EthernetInterface eth;
    static WIC::Client<1000, 1012> client(eth);

    eth.connect();

    client.connect("ws://echo.websocket.org/");

    client.send("hello world!");

    bytes = client.recv(encoding, fin, buffer, 100);

    if((bytes >= 0) && (encoding == WIC_ENCODING_UTF8)){

        printf("got: %.*s\n", bytes, buffer);
    }
            
    client.close();                
}
