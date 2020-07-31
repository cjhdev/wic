#include "mbed.h"
#include "wic_client.hh"

#include <assert.h>

const uint32_t WICClient::socket_open_flag = 1U;

/* constructors *******************************************************/

WICClient::WICClient(NetworkInterface &interface) :
    interface(interface),
    condition(mutex)        
{
    init_arg = {0};

    init_arg.app = this;
    
    init_arg.tx = tx;
    init_arg.tx_max = sizeof(tx);
    init_arg.rx = rx;
    init_arg.rx_max = sizeof(rx);

    init_arg.on_open = handle_open;
    init_arg.on_close = handle_close;
    init_arg.on_text = handle_text;
    init_arg.on_binary = handle_binary;

    init_arg.write = handle_write;
    init_arg.rand = handle_rand;
    
    init_arg.role = WIC_ROLE_CLIENT;


    /* these will block on flags until needed */
    writer_thread.start(callback(this, &WICClient::writer_task));
    reader_thread.start(callback(this, &WICClient::reader_task));
}

/* static methods *****************************************************/

WICClient *
WICClient::to_obj(struct wic_inst *self)
{       
    return static_cast<WICClient *>(wic_get_app(self));
}

void
WICClient::handle_write(struct wic_inst *self, const void *data, size_t size)
{
    WICClient *obj = to_obj(self);

    // this needs to return immediately if there are no buffers
    TXBuffer *buf = obj->output.alloc();

    (void)memcpy(buf->data, data, size);
    buf->size = size;

    obj->output.put(buf);            
}

uint32_t
WICClient::handle_rand(struct wic_inst *self)
{
    // fixme
    return 0xaaaaaaaa;
}

void
WICClient::handle_open(struct wic_inst *self)
{
    printf("handling open\n");            
}

void
WICClient::handle_close(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size)
{
    printf("handling close event\n");   

    WICClient *obj = to_obj(self);
    obj->sock.close();            
}
        
void
WICClient::handle_text(struct wic_inst *self, bool fin, const char *data, uint16_t size)
{
    printf("handling binary event\n");      
}
        
void
WICClient::handle_binary(struct wic_inst *self, bool fin, const void *data, uint16_t size)
{
    printf("handling binary event\n");            
}

/* protected instance methods *****************************************/

void
WICClient::do_parse()
{
    osEvent evt = input.get();

    if(evt.status == osEventMail){

        RXBuffer *buf = (RXBuffer *)evt.value.p;

        wic_parse(&inst, buf->data, buf->size);

        input.free(buf);
    }
}
        
void
WICClient::do_close(bool &done)
{
    wic_close(&inst);
    done = true;
    condition.notify_all();
}

void
WICClient::do_open(bool &done, bool &retval)
{
    SocketAddress a;

    sock.open(&interface);

    interface.gethostbyname(wic_get_url_hostname(&inst), &a);

    a.set_port(wic_get_url_port(&inst));

    nsapi_error_t err = sock.connect(a);

    if(err != NSAPI_ERROR_OK){

        switch(err){
        case NSAPI_ERROR_DNS_FAILURE:
        case NSAPI_ERROR_TIMEOUT:
        case NSAPI_ERROR_CONNECTION_TIMEOUT:
            //ThisThread::sleep_for(5000);
            break;
        default:
            //ThisThread::sleep_for(5000);
            break;
        }

        //requeue?
        //or stay in this event and loop
    }

    /* this should never fail at this point */
    {
        bool ok = wic_init(&inst, &init_arg);
        assert(ok);
    }
    
    /* this might fail if something weird happens like not
     * enough memory for all the headers
     *
     * */
    {
        bool ok = wic_start(&inst);
        assert(ok);
    }

    flags.set(socket_open_flag);

    /* now we actually have to wait for the thign to open */
    
        
    done = true;
    retval = true;
}

void
WICClient::do_tick()
{    
}

void
WICClient::do_send_text(bool &done, bool &retval, bool fin, const char *value, uint16_t size)
{
    retval = wic_send_text(&inst, fin, value, size);
    done = true;
    condition.notify_all();        
}

void
WICClient::do_send_binary(bool &done, bool &retval, bool fin, const void *value, uint16_t size)
{
    retval = wic_send_binary(&inst, fin, value, size);
    done = true;
    condition.notify_all();        
}

void
WICClient::do_signal_socket_error()
{
    
}

void
WICClient::writer_task(void)
{
    osEvent evt;
    TXBuffer *buf;
    
    for(;;){

        flags.wait_any(socket_open_flag);

        for(;;){

            evt = output.get();
            buf = (TXBuffer *)evt.value.p;
            
            if(sock.send(buf->data, buf->size) != NSAPI_ERROR_OK){

                //signal failure to event loop, finalize thread
            }                
        
            output.free(buf);
        }

        flags.clear(socket_open_flag);
    }
}        
        
void
WICClient::reader_task(void)
{
    nsapi_size_or_error_t retval;
    RXBuffer *buf;

    for(;;){

        flags.wait_any(socket_open_flag);

        for(;;){

            buf = input.alloc();

            retval = sock.recv(buf->data, sizeof(buf->data));

            if(retval < 0){

                // signal failure to event loop

                input.free(buf);    
                break;
            }
            
            buf->size = retval;

            input.put(buf);
            queue.event(this, &WICClient::do_parse);                
        }

        flags.clear(socket_open_flag);
    }
}

/* public instance methods ********************************************/

bool
WICClient::open(const char *url)
{
    bool retval = false;
    bool done = false;
    
    mutex.lock();

    do_open(done, retval);

    while(!done){
    
        condition.wait();
    }

    mutex.unlock();

    return retval;
}

void
WICClient::close()
{
    mutex.lock();

    bool done = false;

    do_close(done);

    while(!done){
    
        condition.wait();
    }

    mutex.unlock();
}

bool
WICClient::text(const char *value)
{
    return text(true, value);
}

bool
WICClient::text(const char *value, uint16_t size)
{
    return text(true, value, size);
}

bool
WICClient::text(bool fin, const char *value)
{   
    bool retval = false;
    int size = strlen(value);

    if((size >= 0) && (size <= UINT16_MAX)){

        retval = text(fin, value, (uint16_t)size);
    }

    return retval;
}

bool
WICClient::text(bool fin, const char *value, uint16_t size)
{
    bool retval = false;
    bool done = false;

    mutex.lock();

    do_send_text(done, retval, fin, value, size);

    while(!done){
    
        condition.wait();
    }

    mutex.unlock();

    return retval;
}

bool
WICClient::binary(const void *value, uint16_t size)
{
    return binary(true, value, size);
}

bool
WICClient::binary(bool fin, const void *value, uint16_t size)
{
    bool retval = false;
    bool done = false;

    mutex.lock();

    do_send_binary(done, retval, fin, value, size);
    
    while(!done){
    
        condition.wait();
    }

    mutex.unlock();

    return retval;
}

bool
WICClient::is_open()
{
    return(wic_get_state(&inst) == WIC_STATE_OPEN);
}
