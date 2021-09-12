#include "wic_plus.h"

#include <random>

using namespace WIC;

Client::Client(
    size_t rx_max
)
    :
    open(false)
{
}

int
Client::connect(const char *url)
{
    struct wic_init_arg arg;

    wic_init(&inst, &arg);

    return -1;
}

void
Client::close()
{
    wic_close(&inst);
}

int
Client::recv(enum wic_encoding& encoding, bool &fin, char *buffer, size_t max, Client::timeout timeout)
{
    (void)encoding;
    (void)fin;
    (void)buffer;
    (void)max;
    (void)timeout;

    return -1;
}

int
Client::send_binary(const char *data, size_t size)
{
    int retval = -1;
    enum wic_status status;

    if(size < UINT16_MAX){

        status = wic_send(&inst, WIC_ENCODING_BINARY, true, data, size);

        switch(status){
        case WIC_STATUS_SUCCESS:
            retval = 0;
            break;
        default:
            break;
        }
    }

    return retval;
}

int
Client::send_utf8(const char *data, size_t size)
{
    int retval = -1;
    enum wic_status status;

    if(size < UINT16_MAX){

        status = wic_send(&inst, WIC_ENCODING_UTF8, true, data, size);

        switch(status){
        case WIC_STATUS_SUCCESS:
            retval = 0;
            break;
        default:
            break;
        }
    }

    return retval;
}

Client *get_self(struct wic_inst *inst)
{
    return reinterpret_cast<Client *>(wic_get_app(inst));
}

bool
Client::on_message_handler(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size)
{
    //auto self = get_self(inst);

    return false;
}

void
Client::on_open_handler(struct wic_inst *inst)
{

}

void
Client::on_handshake_failure_handler(struct wic_inst *inst, enum wic_handshake_failure reason)
{

}

void
Client::on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size)
{
    get_self(inst)->open = false;
}

void
Client::on_close_transport_handler(struct wic_inst *inst)
{
    get_self(inst)->transport.close();
}

void
Client::on_send_handler(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type)
{
    //auto self = get_self(inst);
}

void
Client::on_buffer_handler(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size)
{

}

uint32_t
Client::rand_handler(struct wic_inst *inst)
{
    std::random_device generator;
    std::uniform_int_distribution<uint32_t> distribution;

    return distribution(generator);
}

