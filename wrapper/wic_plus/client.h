#ifndef CLIENT_H
#define CLIENT_H

#include "wic.h"
#include "transport.h"

#include <chrono>
#include <vector>

namespace WIC {

    class Client {

    public:

        Client(
            size_t rx_max = 1024
        );

        virtual ~Client();

        int connect(const char *url);

        void close();

        using timeout = std::chrono::duration<unsigned, std::chrono::seconds>;

        int recv(enum wic_encoding& encoding, bool &fin, char *buffer, size_t max, Client::timeout timeout);

        int send_binary(const char *data, size_t size);
        int send_utf8(const char *data, size_t size);

    private:

        wic_inst inst;

        Transport transport;

        std::vector<uint8_t> rx_buffer;

        bool open;

        static bool on_message_handler(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size);
        static void on_open_handler(struct wic_inst *inst);
        static void on_handshake_failure_handler(struct wic_inst *inst, enum wic_handshake_failure reason);
        static void on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);
        static void on_close_transport_handler(struct wic_inst *inst);
        static void on_send_handler(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type);
        static void on_buffer_handler(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size);
        static uint32_t rand_handler(struct wic_inst *inst);

        static Client *get_self(struct wic_inst *inst);
    };
};

#endif
