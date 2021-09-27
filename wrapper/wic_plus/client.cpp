#include "wic_plus.h"

#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <random>
#include <iostream>

using namespace WIC;
using boost::asio::ip::tcp;

Client::Client(
    size_t rx_max,
    size_t tx_max
)
    :
    s(io_context),
    user_buffer_sem(1),
    ping_buffer_sem(1),
    pong_buffer_sem(1),
    close_buffer_sem(1),
    handshake_sem(0),
    open(false)
{
    rx_buffer.resize(rx_max);
    user_buffer.resize(tx_max);
}

Client::~Client()
{
}

wic_status
Client::connect(const char *url)
{
    struct wic_init_arg arg{0};

    enum wic_status status;

    Semaphore flag(0);

    handshake_success = false;

    arg.rx = rx_buffer.data();
    arg.rx_max = rx_buffer.size();

    arg.on_message = on_message_handler;
    arg.on_open = on_open_handler;
    arg.on_handshake_failure = on_handshake_failure_handler;
    arg.on_close = on_close_handler;
    arg.on_close_transport = on_close_transport_handler;
    arg.on_send = on_send_handler;
    arg.on_buffer = on_buffer_handler;
    arg.rand = rand_handler;

    arg.app = this;

    arg.url = url;

    arg.role = WIC_ROLE_CLIENT;

    if(wic_init(&inst, &arg)){

        char bs[8];

        snprintf(bs, sizeof(bs), "%" PRIu16, wic_get_url_port(&inst));

        tcp::resolver resolver(io_context);

        auto endpoints = resolver.resolve(wic_get_url_hostname(&inst), bs);

        WIC_DEBUG("ready to connect")

        boost::asio::async_connect(s, endpoints,
            [this, &status, &flag](boost::system::error_code ec, tcp::endpoint){

                WIC_DEBUG("connected")

                if(!ec){

                    status = wic_start(&inst);

                    if(status == WIC_STATUS_SUCCESS){

                        do_read(this);
                    }
                }
                else{

                    status = WIC_STATUS_NOT_OPEN;
                }

                flag.release();
            }
        );

        flag.acquire();

        if(status == WIC_STATUS_SUCCESS){

            handshake_sem.acquire();

            if(handshake_success){

                status = WIC_STATUS_SUCCESS;

                open = true;
            }
            else{

                status = WIC_STATUS_NOT_OPEN;
            }
        }
    }

    return status;
}

void
Client::close()
{
    Semaphore flag(0);

    boost::asio::post(io_context,
        [this, &flag](){

            wic_close(&inst);

            flag.release();
        }
    );

    flag.acquire();
}

wic_status
Client::recv(enum wic_encoding& encoding, bool &fin, char *buffer, size_t max)
{
    wic_status status = WIC_STATUS_TIMEOUT;
    Semaphore flag(0);

    (void)encoding;
    (void)fin;
    (void)buffer;
    (void)max;

    do{

    }
    while(0);

    // read buffer if available

    return status;
}

wic_status
Client::send_binary(const void *data, size_t size, bool fin)
{
    return send((char *)data, size, fin, WIC_ENCODING_BINARY);
}

wic_status
Client::send_utf8(const std::string &data, bool fin)
{
    return send_utf8(data.data(), data.size(), fin);
}

wic_status
Client::send_utf8(const char *data, bool fin)
{
    return send_utf8(data, strlen(data), fin);
}

wic_status
Client::send_utf8(const char *data, size_t size, bool fin)
{
    return send(data, size, fin, WIC_ENCODING_UTF8);
}

wic_status
Client::send(const char *data, size_t size, bool fin, wic_encoding encoding)
{
    wic_status status;
    Semaphore flag(0);

    do{

        boost::asio::post(io_context,
            [this, &flag, &status, encoding, data, size, fin](){

                status = wic_send(&inst, encoding, fin, data, size);

                flag.release();
            }
        );

        flag.acquire();

        if(status == WIC_STATUS_WOULD_BLOCK){

            user_buffer_sem.acquire();
        }
    }
    while(status == WIC_STATUS_WOULD_BLOCK);

    return status;
}

Client *
Client::get_self(struct wic_inst *inst)
{
    return reinterpret_cast<Client *>(wic_get_app(inst));
}

bool
Client::on_message_handler(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size)
{
    //auto self = get_self(inst);

    (void)inst;
    (void)encoding;
    (void)fin;
    (void)data;
    (void)size;

    return false;
}

void
Client::on_open_handler(struct wic_inst *inst)
{
    auto self = get_self(inst);

    self->handshake_success = true;

    self->handshake_sem.release();
}

void
Client::on_handshake_failure_handler(struct wic_inst *inst, enum wic_handshake_failure reason)
{
    auto self = get_self(inst);

    self->handshake_success = false;
    self->handshake_fail_reason = reason;

    self->handshake_sem.release();
}

void
Client::on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size)
{
    (void)code;
    (void)reason;
    (void)size;

    auto self = get_self(inst);

    self->open = false;
}

void
Client::on_close_transport_handler(struct wic_inst *inst)
{
    auto self = get_self(inst);

    self->s.close();
}

void
Client::on_send_handler(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type)
{
    auto self = get_self(inst);

    WIC_DEBUG("sending...")

    self->s.async_send(
        boost::asio::buffer(data, size),
        [self, type](boost::system::error_code ec, std::size_t bytes){



            (void)bytes;

            switch(type){
            default:
            case WIC_BUFFER_HTTP:
            case WIC_BUFFER_USER:

                self->user_buffer_sem.release();
                break;

            case WIC_BUFFER_PING:

                self->ping_buffer_sem.release();
                break;

            case WIC_BUFFER_PONG:

                self->pong_buffer_sem.release();
                break;

            case WIC_BUFFER_CLOSE:
            case WIC_BUFFER_CLOSE_RESPONSE:

                self->close_buffer_sem.release();
                break;
            }

            if(!ec){

                wic_close_with_reason(&self->inst, wic_convert_close_reason(WIC_CLOSE_REASON_ABNORMAL_2), nullptr, 0);
            }
        }
    );
}

void *
Client::on_buffer_handler(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size)
{
    auto self = get_self(inst);
    void *retval = nullptr;

    switch(type){
    default:
    case WIC_BUFFER_HTTP:
    case WIC_BUFFER_USER:

        if(self->user_buffer_sem.try_acquire()){

            if(min_size <= self->user_buffer.size()){

                retval = self->user_buffer.data();
                *max_size = self->user_buffer.size();
            }
        }
        break;

    case WIC_BUFFER_PING:

        if(self->ping_buffer_sem.try_acquire()){

            retval = self->ping_buffer.data();
            *max_size = self->ping_buffer.max_size();
        }
        break;

    case WIC_BUFFER_PONG:

        if(self->pong_buffer_sem.try_acquire()){

            retval = self->pong_buffer.data();
            *max_size = self->pong_buffer.max_size();
        }
        break;

    case WIC_BUFFER_CLOSE:
    case WIC_BUFFER_CLOSE_RESPONSE:

        if(self->close_buffer_sem.try_acquire()){

            retval = self->close_buffer.data();
            *max_size = self->close_buffer.max_size();
        }
        break;
    }

    return retval;
}

uint32_t
Client::rand_handler(struct wic_inst *inst)
{
    std::random_device generator;
    std::uniform_int_distribution<uint32_t> distribution;

    return distribution(generator);
}

void
Client::do_read(Client *self)
{
    self->s.async_read_some(
        boost::asio::buffer(self->socket_buffer.data(), self->socket_buffer.size()),
        [self](boost::system::error_code ec, std::size_t bytes){
            if(!ec){

                size_t retval;

                for(size_t pos=0; pos < bytes; pos += retval){

                    retval = wic_parse(&self->inst, &self->socket_buffer.data()[pos], bytes - pos);
                }

                do_read(self);
            }
            else{

                wic_close_with_reason(&self->inst, wic_convert_close_reason(WIC_CLOSE_REASON_ABNORMAL_2), nullptr, 0);
            }
        }
    );
}
