#include "mbed.h"
#include "wic_client.hpp"

#include <assert.h>

const uint32_t WICClient::socket_open_flag = 1U;

/* constructors *******************************************************/

WICClient::WICClient(NetworkInterface &interface) :
    interface(interface),
    condition(mutex),
    on_text_cb(nullptr),
    on_binary_cb(nullptr),
    on_open_cb(nullptr),
    on_close_cb(nullptr)
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

    event_thread.start(callback(&events, &EventQueue::dispatch_forever));
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
    WICClient *obj = to_obj(self);

    obj->events.cancel(obj->timeout_id);
    
    if(obj->on_open_cb){

        obj->on_open_cb();
    }
}

void
WICClient::handle_close(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size)
{
    WICClient *obj = to_obj(self);
    obj->sock.close();

    if(obj->on_close_cb){

        obj->on_close_cb(code, reason, size);
    }
}
        
void
WICClient::handle_text(struct wic_inst *self, bool fin, const char *data, uint16_t size)
{
    WICClient *obj = to_obj(self);
    
    if(obj->on_text_cb){

        obj->on_text_cb(fin, data, size);
    }    
}
        
void
WICClient::handle_binary(struct wic_inst *self, bool fin, const void *data, uint16_t size)
{
    WICClient *obj = to_obj(self);
    
    if(obj->on_binary_cb){

        obj->on_binary_cb(fin, data, size);
    }   
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
WICClient::do_close_with_reason(bool &done, uint16_t code, const char *reason, uint16_t size)
{
    wic_close_with_reason(&inst, code, reason, size);
    done = true;
    condition.notify_all();
}

void
WICClient::do_timeout(bool &done)
{
    do_close(done);
}

void
WICClient::do_open(bool &done, bool &retval)
{
    SocketAddress a;
    nsapi_error_t err;

    if(!wic_init(&inst, &init_arg)){

        done = true;
        return;
    }

    err = interface.gethostbyname(wic_get_url_hostname(&inst), &a);

    if(err != NSAPI_ERROR_OK){

        done = true;
        return;
    }

    sock.open(&interface);

    a.set_port(wic_get_url_port(&inst));

    err = sock.connect(a);

    if(err != NSAPI_ERROR_OK){

        sock.close();
        done = true;
        return;
    }

    if(!wic_start(&inst)){

        sock.close();
        done = true;
        return;
    }

    flags.set(socket_open_flag);

    timeout_id = events.call_in(5000, callback(this, &WICClient::do_timeout), done);
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
WICClient::do_signal_socket_error(uint16_t code)
{
    wic_close_with_reason(&inst, code, NULL, 0U);
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

                events.call(callback(this, &WICClient::do_signal_socket_error), WIC_CLOSE_PROTOCOL_ERROR);
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

                events.call(callback(this, &WICClient::do_signal_socket_error), WIC_CLOSE_PROTOCOL_ERROR);

                input.free(buf);    
                break;
            }
            
            buf->size = retval;

            input.put(buf);
            events.call(this, &WICClient::do_parse);                
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

    events.call(callback(this, &WICClient::do_open), done, retval);

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

    events.call(callback(this, &WICClient::do_close), done);

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

    events.call(callback(this, &WICClient::do_send_text), done, retval, fin, value, size);

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

    events.call(callback(this, &WICClient::do_send_binary), done, retval, fin, value, size);

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

void
WICClient::on_text(Callback<void(bool,const char *, uint16_t)> handler)
{
    on_text_cb = handler;
}

void
WICClient::on_binary(Callback<void(bool,const void *, uint16_t)> handler)
{
    on_binary_cb = handler;
}

void
WICClient::on_open(Callback<void()> handler)
{
    on_open_cb = handler;
}

void
WICClient::on_close(Callback<void(uint16_t, const char *, uint16_t)> handler)
{
    on_close_cb = handler;
}
