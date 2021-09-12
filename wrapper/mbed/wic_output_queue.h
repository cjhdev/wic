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

#ifndef WIC_OUTPUT_QUEUE_H
#define WIC_OUTPUT_QUEUE_H

#include "mbed.h"
#include "wic.h"
#include "wic_buffer.h"

namespace WIC {

    class OutputQueueBase {

        public:

            virtual BufferBase *alloc(enum wic_buffer type, size_t min_size, size_t *max) = 0;
            virtual void free(BufferBase *buf) = 0;

            virtual osStatus put(BufferBase *buf) = 0;            
            virtual BufferBase *get(bool& close) = 0;            
    };

    template<size_t MAX_SIZE>
    class OutputQueue : public OutputQueueBase {

        protected:

            Buffer<MAX_SIZE> user;
            Buffer<131> close;
            Buffer<2> ping;
            Buffer<131> pong;

            EventFlags flags;

            /* 4 + poison */
            rtos::Queue<BufferBase, 5> queue;

            BufferBase *type_to_buf(enum wic_buffer type)
            {
                BufferBase *retval = nullptr;

                switch(type){
                case WIC_BUFFER_HTTP:
                case WIC_BUFFER_USER:
                    retval = &user;
                    break;
                case WIC_BUFFER_CLOSE:
                case WIC_BUFFER_CLOSE_RESPONSE:
                    retval = &close;
                    break;
                case WIC_BUFFER_PONG:
                    retval = &pong;
                    break;
                case WIC_BUFFER_PING:
                    retval = &ping;
                    break;
                }

                return retval;
            }
                
        public:

            OutputQueue() :
                user(1U, 0U),
                close(2U, 3U),  // priority 2 is nullptr
                ping(4U, 0U),
                pong(8U, 1U)
            {}

            BufferBase *alloc(enum wic_buffer type, size_t min_size, size_t *max)
            {
                BufferBase *retval = nullptr;         
                BufferBase *buf = type_to_buf(type);

                *max = MAX_SIZE;

                if(min_size == 0U || buf->max >= min_size){

                    if((buf->mask & flags.get()) == 0U){

                        flags.set(buf->mask);
                        retval = buf;
                    }
                }

                return retval;
            }

            osStatus put(BufferBase *buf)
            {
                osStatus retval;
        
                if(buf){

                    retval = queue.put(buf, buf->priority);                    
                }
                else{

                    retval = queue.put(buf, 2U);
                }

                return retval;
            }

            void free(BufferBase *buf)
            {
                if(buf){

                    flags.clear(buf->mask);
                }
            }
            
            BufferBase *get(bool& close)
            {
                BufferBase *retval = nullptr;
                osEvent evt = queue.get(0U);

                close = false;

                if(evt.status == osEventMessage){

                    retval = static_cast<BufferBase *>(evt.value.p);

                    close = retval ? false : true;
                }

                return retval;
            }
    };
}

#endif
