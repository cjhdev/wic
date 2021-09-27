#ifndef CLIENT_H
#define CLIENT_H

#include "wic.h"
#include "semaphore.h"

#include <chrono>
#include <vector>
#include <thread>
#include <boost/asio.hpp>

namespace WIC {

    class Client {

    public:

        Client(size_t rx_max = 1024, size_t tx_max = 1024);

        virtual ~Client();

        wic_status connect(const char *url);

        void close();

        using timeout = std::chrono::duration<unsigned, std::chrono::seconds>;

        wic_status recv(enum wic_encoding& encoding, bool &fin, char *buffer, size_t max);

        wic_status send_binary(const void *data, size_t size, bool fin = true);

        wic_status send_utf8(const char *data, size_t size, bool fin = true);
        wic_status send_utf8(const char *data, bool fin = true);
        wic_status send_utf8(const std::string &data, bool fin = true);

    private:

        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket s;

        Semaphore user_buffer_sem;
        Semaphore ping_buffer_sem;
        Semaphore pong_buffer_sem;
        Semaphore close_buffer_sem;

        Semaphore handshake_sem;
        bool handshake_success;
        wic_handshake_failure handshake_fail_reason;

        wic_inst inst;

        // at this time we have one user buffer for incoming utf and bin data
        std::vector<uint8_t> rx_buffer;

        // at this time we have one user buffer for outgoing utf and bin data
        std::vector<uint8_t> user_buffer;

        // fixed size buffers required for sending pings, pongs, and closes
        std::array<uint8_t, 2> ping_buffer;
        std::array<uint8_t, 131> pong_buffer;
        std::array<uint8_t, 131> close_buffer;

        // temporary read buffer used to shuttle chunks from socket to wic state machine
        std::array<uint8_t, 512> socket_buffer;

        bool open;

        std::thread t;

        static bool on_message_handler(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size);
        static void on_open_handler(struct wic_inst *inst);
        static void on_handshake_failure_handler(struct wic_inst *inst, enum wic_handshake_failure reason);
        static void on_close_handler(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);
        static void on_close_transport_handler(struct wic_inst *inst);
        static void on_send_handler(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type);
        static void *on_buffer_handler(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size);
        static uint32_t rand_handler(struct wic_inst *inst);

        static Client *get_self(struct wic_inst *inst);

        static void do_read(Client *self);

        wic_status send(const char *data, size_t size, bool fin, wic_encoding encoding);
    };
};

#endif
