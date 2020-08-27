#include "wic_client.h"

using namespace WIC;

/* constructors *******************************************************/

ClientBase::ClientBase(NetworkInterface &interface, InputQueueBase& input_queue, OutputQueueBase& tx_queue, BufferBase& url) :
    interface(interface),
    input_queue(input_queue),
    tx_queue(tx_queue),
    url(url),
    tls(&tcp),
    socket(&tcp),
    writers(0, 1),
    events(100 * EVENTS_EVENT_SIZE),
    readers(readers_mutex)
{
    socket->sigio(callback(this, &ClientBase::do_sigio));
    worker_thread.start(callback(this, &ClientBase::worker_task));
    ticker.attach_us(callback(this, &ClientBase::do_tick), 1000000UL);
}

/* static protected ***************************************************/

ClientBase *
ClientBase::to_obj(struct wic_inst *self)
{
    return static_cast<ClientBase *>(wic_get_app(self));
}

void
ClientBase::handle_send(struct wic_inst *self, const void *data, size_t size, enum wic_buffer type)
{
    ClientBase *obj = to_obj(self);

    if(obj->tx){

        obj->tx->size = size;

        if(size == 0){

            obj->tx_queue.free(obj->tx);
        }
        else{

            obj->tx_queue.put(obj->tx);
        }

        obj->tx = nullptr;
        obj->do_work();
    }
}

void *
ClientBase::handle_buffer(struct wic_inst *self, size_t size, enum wic_buffer type, size_t *max)
{
    void *retval = NULL;
    ClientBase *obj = to_obj(self);

    obj->tx = obj->tx_queue.alloc(type, size, max);

    if(obj->tx){

        retval = obj->tx->data;
    }

    return retval;
}

uint32_t
ClientBase::handle_rand(struct wic_inst *self)
{
    return rand();
}

void
ClientBase::handle_handshake_failure(struct wic_inst *self, enum wic_handshake_failure reason)
{
    ClientBase *obj = to_obj(self);

    obj->events.cancel(obj->timeout_id);

    obj->job.handshake_failure_reason = reason;

    switch(reason){
    default:
    /* no response within timeout (either socket or message timeout) */
    case WIC_HANDSHAKE_FAILURE_ABNORMAL_1:
        obj->job.retval = NSAPI_ERROR_CONNECTION_TIMEOUT;
        break;

    /* socket closed / transport errored */
    case WIC_HANDSHAKE_FAILURE_ABNORMAL_2:
        obj->job.retval = NSAPI_ERROR_CONNECTION_LOST;
        break;

    /* response was not HTTP */
    case WIC_HANDSHAKE_FAILURE_PROTOCOL:
        obj->job.retval = NSAPI_ERROR_UNSUPPORTED;
        break;

    /* connection was not upgraded */
    case WIC_HANDSHAKE_FAILURE_UPGRADE:
        obj->job.retval = NSAPI_ERROR_UNSUPPORTED;
        break;
    }

    obj->job.done = true;
    obj->notify_writers();

    obj->state = CLOSING;
}

void
ClientBase::handle_open(struct wic_inst *self)
{
    ClientBase *obj = to_obj(self);

    obj->events.cancel(obj->timeout_id);

    obj->state = OPEN;

    obj->job.retval = NSAPI_ERROR_OK;
    obj->job.done = true;
    obj->notify_writers();
}

bool
ClientBase::handle_message(struct wic_inst *self, enum wic_encoding encoding, bool fin, const char *data, uint16_t size)
{
    bool retval = false;
    ClientBase *obj = to_obj(self);
    BufferBase *ptr = obj->input_queue.alloc();

    if(ptr){

        ptr->init(data, size, encoding, fin);

        obj->input_queue.put(ptr);

        retval = true;
    }

    obj->notify_readers();

    return retval;
}

void
ClientBase::handle_close(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size)
{
    ClientBase *obj = to_obj(self);

    obj->state = CLOSING;
}

void
ClientBase::handle_close_transport(struct wic_inst *self)
{
    /* this ensures that the output queue is flushed */
    to_obj(self)->tx_queue.put(nullptr);
    to_obj(self)->do_work();
}

void
ClientBase::handle_ping(struct wic_inst *self)
{
    //ClientBase *obj = to_obj(self);
}

void
ClientBase::handle_pong(struct wic_inst *self)
{
    //ClientBase *obj = to_obj(self);
}

/* protected **********************************************************/

void
ClientBase::do_work()
{
    work.release();
}

void
ClientBase::do_close_socket()
{
    socket->close();
    job.done = true;
    state = CLOSED;
    notify_readers();
    notify_writers();
}

void
ClientBase::do_open()
{
    SocketAddress a;
    nsapi_error_t err;

    if(!rx){

        rx = input_queue.alloc();
    }

    struct wic_init_arg init_arg = {0};

    if(state != CLOSED){

        switch(state){
        default:
        case OPENING:
        case CLOSING:
            job.retval = NSAPI_ERROR_BUSY;
            break;
        case OPEN:
            job.retval = NSAPI_ERROR_IS_CONNECTED;
            break;
        }

        job.done = true;
        notify_writers();
        return;
    }

    flush_input_queue();

    init_arg.app = this;

    init_arg.rx = rx->data;
    init_arg.rx_max = rx->max;

    init_arg.on_open = handle_open;
    init_arg.on_close = handle_close;
    init_arg.on_message = handle_message;
    init_arg.on_close_transport = handle_close_transport;
    init_arg.on_handshake_failure = handle_handshake_failure;

    init_arg.on_send = handle_send;
    init_arg.on_buffer = handle_buffer;
    init_arg.rand = handle_rand;

    init_arg.role = WIC_ROLE_CLIENT;

    init_arg.url = (const char *)url.data;

    if(!wic_init(&inst, &init_arg)){

        job.retval = NSAPI_ERROR_PARAMETER;
        do_close_socket();
        return;
    }

    err = interface.gethostbyname(wic_get_url_hostname(&inst), &a);

    if(err != NSAPI_ERROR_OK){

        job.retval = err;
        do_close_socket();
        return;
    }

    a.set_port(wic_get_url_port(&inst));

    switch(wic_get_url_schema(&inst)){
    default:
    case WIC_SCHEMA_HTTP:
    case WIC_SCHEMA_WS:
        socket = &tcp;
        break;
    case WIC_SCHEMA_HTTPS:
    case WIC_SCHEMA_WSS:
        socket = &tls;
        break;
    }

    (void)tcp.open(&interface);

    err = socket->connect(a);

    if(err != NSAPI_ERROR_OK){

        job.retval = err;
        do_close_socket();
        return;
    }

    socket->set_blocking(false);

    job.status = wic_start(&inst);

    if(job.status != WIC_STATUS_SUCCESS){

        job.retval = NSAPI_ERROR_OK;
        do_close_socket();
        return;
    }

    state = OPENING;

    timeout_id = events.call_in(5000, callback(this, &ClientBase::do_handshake_timeout));
}

void
ClientBase::do_close()
{
    switch(wic_get_state(&inst)){
    case WIC_STATE_READY:
    case WIC_STATE_OPEN:
        wic_close(&inst);
        break;
    case WIC_STATE_INIT:
    case WIC_STATE_CLOSED:
    default:
        job.retval = NSAPI_ERROR_OK;
        job.done = true;
        notify_writers();
        break;
    }
}

void
ClientBase::do_send(enum wic_encoding encoding, bool fin, const char *value, uint16_t size)
{
    job.status = wic_send(&inst, encoding, fin, value, size);
    job.done = true;
    notify_writers();
}

void
ClientBase::do_handshake_timeout()
{
    wic_close_with_reason(&inst, WIC_CLOSE_ABNORMAL_1, NULL, 0U);
}

void
ClientBase::worker_task()
{
    nsapi_size_or_error_t retval;
    size_t tx_pos = 0U;
    size_t rx_pos = 0U;
    RXBuffer *_rx = nullptr;
    BufferBase *_tx = nullptr;

    for(;;){

        work.acquire();

        events.dispatch(0);

        if(state != CLOSED){

            wic_parse(&inst, NULL, 0U);
        }

        /* try to get an RX buffer */
        if(!_rx){

            _rx = rx_pool.alloc();

            if(_rx){

                _rx = new(_rx)RXBuffer;
            }

            rx_pos = 0U;
        }

        /* try to read the socket if there is a zeroed RX buffer */
        if(_rx && (_rx->size == 0U)){

            retval = socket->recv(_rx->data, _rx->max);

            if(retval > 0){

                _rx->size = retval;
            }
            else{

                switch(retval){
                case NSAPI_ERROR_WOULD_BLOCK:
                case NSAPI_ERROR_NO_SOCKET:
                    break;
                default:

                    wic_close_with_reason(&inst, WIC_CLOSE_ABNORMAL_2, NULL, 0U);
                    do_work();
                    rx_pool.free(_rx);
                    _rx = nullptr;
                }
            }
        }

        /* try to parse the data read from socket */
        if(_rx && (_rx->size > 0U)){

            size_t bytes = wic_parse(&inst, &_rx->data[rx_pos], _rx->size - rx_pos);

            rx_pos += bytes;

            if(rx_pos == _rx->size){

                rx_pool.free(_rx);
                _rx = nullptr;
                do_work();
            }
        }

        /* try to get a TX buffer */
        if(!_tx){

            bool close;

            _tx = tx_queue.get(close);
            tx_pos = 0U;

            if(close){

                for(_tx = tx_queue.get(close); _tx; _tx = tx_queue.get(close)){

                    tx_queue.free(_tx);
                }

                _tx = nullptr;

                do_close_socket();
                do_work();
            }
        }

        /* try to write the TX buffer to the socket */
        if(_tx){

            size_t to_write = _tx->size - tx_pos;

            to_write = (to_write > MBED_CONF_WIC_MSS) ? MBED_CONF_WIC_MSS : to_write;

            retval = socket->send(&_tx->data[tx_pos], to_write);

            if(retval >= 0){

                tx_pos += retval;

                if(tx_pos == _tx->size){

                    tx_queue.free(_tx);
                    _tx = nullptr;
                    notify_writers();
                    do_work();
                }
            }
            else{

                switch(retval){
                case NSAPI_ERROR_WOULD_BLOCK:
                    break;
                default:

                    tx_queue.free(_tx);
                    _tx = nullptr;
                    notify_writers();
                    do_work();
                    break;
                }
            }
        }
    }
}

/* public *************************************************************/

nsapi_error_t
ClientBase::connect(const char *url)
{
    uint32_t n = max_redirects;
    nsapi_error_t retval = NSAPI_ERROR_PARAMETER;
    const char *url_ptr = url;

    writers_mutex.lock();

    for(;;){

        job = {};

        /* URLs cannot be larger than what we can
         * buffer.
         *
         * We buffer so as to support
         * redirects */
        if(strlen(url_ptr) >= this->url.max){

            break;
        }

        this->url.size = strlen(url_ptr)+1U;
        strcpy((char *)this->url.data, url_ptr);

        events.call(callback(this, &ClientBase::do_open));
        do_work();

        while(!job.done){

            wait();
        }

        if(
            (job.handshake_failure_reason == WIC_HANDSHAKE_FAILURE_UPGRADE)
            &&
            (wic_get_redirect_url(&inst) != NULL)
            &&
            (n > 0U)
        ){

            n--;
            url_ptr = wic_get_redirect_url(&inst);
        }
        else{

            retval = job.retval;
            break;
        }
    }

    writers_mutex.unlock();

    return retval;
}

void
ClientBase::close()
{
    writers_mutex.lock();

    job = {0};

    events.call(callback(this, &ClientBase::do_close));
    do_work();

    while(!job.done){

        wait();
    }

    writers_mutex.unlock();
}

nsapi_size_or_error_t
ClientBase::send(const char *data, uint16_t size, enum wic_encoding encoding, bool fin)
{
    nsapi_size_or_error_t retval = NSAPI_ERROR_PARAMETER;

    if(size > 1000){

        
    }

    writers_mutex.lock();

    for(;;){

        job = {0};

        events.call(callback(this, &ClientBase::do_send), encoding, fin, data, size);

        do_work();

        while(!job.done){

            wait();
        }

        if(job.status == WIC_STATUS_WOULD_BLOCK){

            wait();
        }
        else{

            switch(job.status){
            case WIC_STATUS_SUCCESS:
                retval = size;
                break;
            default:
                retval = NSAPI_ERROR_PARAMETER;
                break;
            }

            break;
        }
    }

    writers_mutex.unlock();

    return retval;
}

bool
ClientBase::try_get(nsapi_size_or_error_t &retval, enum wic_encoding& encoding, bool &fin, char *buffer, size_t max)
{
    bool success = false;
    osEvent evt;
    BufferBase *ptr;

    evt = input_queue.get(0);

    if(evt.status == osEventMail){

        ptr = static_cast<BufferBase *>(evt.value.p);

        encoding = ptr->encoding;
        fin = ptr->fin;
        retval = (ptr->size > max) ? max : ptr->size;
        (void)memcpy(buffer, ptr->data, retval);

        input_queue.free(ptr);
        do_work();

        success = true;
    }
    else{

        retval = NSAPI_ERROR_WOULD_BLOCK;
    }

    return success;
}


nsapi_size_or_error_t
ClientBase::recv(enum wic_encoding& encoding, bool &fin, char *buffer, size_t max, uint32_t timeout)
{
    nsapi_size_or_error_t retval;
    uint64_t until = 0;

    readers_mutex.lock();

    if(timeout != osWaitForever){

        until = Kernel::get_ms_count() + timeout;
    }

    for(;;){

        if(try_get(retval, encoding, fin, buffer, max)){

            break;
        }
        else{

            if(state == CLOSED){

                retval = NSAPI_ERROR_NO_CONNECTION;
                break;
            }

            if(timeout == osWaitForever){

                readers.wait();
            }
            else if(readers.wait_until(until)){

                retval = (state == OPEN) ? NSAPI_ERROR_WOULD_BLOCK : NSAPI_ERROR_NO_CONNECTION;
                break;
            }
            else{

                //go around
            }
        }
    }

    readers_mutex.unlock();

    return retval;
}

bool
ClientBase::is_open()
{
    return state == OPEN;
}

nsapi_error_t
ClientBase::set_root_ca_cert(const void *root_ca, size_t len)
{
    return tls.set_root_ca_cert(root_ca, len);
}

nsapi_error_t
ClientBase::set_root_ca_cert(const char *root_ca_pem)
{
    return tls.set_root_ca_cert(root_ca_pem);
}

nsapi_error_t
ClientBase::set_client_cert_key(const char *client_cert_pem, const char *client_private_key_pem)
{
    return tls.set_client_cert_key(client_cert_pem, client_private_key_pem);
}

nsapi_error_t
ClientBase::set_client_cert_key(const void *client_cert_pem, size_t client_cert_len, const void *client_private_key_pem, size_t client_private_key_len)
{
    return tls.set_client_cert_key(client_cert_pem, client_cert_len, client_private_key_pem, client_private_key_len);
}
