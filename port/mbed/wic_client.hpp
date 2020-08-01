#include "mbed.h"
#include "wic.h"

class WICClient {

    protected:

        static const uint32_t socket_open_flag;

        int timeout_id;

        uint8_t tx[1012U];
        uint8_t rx[1000U];

        NetworkInterface &interface;
        TCPSocket sock;
        Mutex mutex;
        ConditionVariable condition;
        EventQueue events;
        EventFlags flags;

        /* two very similar structures so we can have
         * different buffer sizes on tx and rx */
        struct TXBuffer {

            uint8_t data[sizeof(tx)];
            size_t size;
        };        
        struct RXBuffer {

            uint8_t data[sizeof(rx)];
            size_t size;
        };

        Mail<TXBuffer, 1> output;
        Mail<RXBuffer, 1> input;

        Thread writer_thread;        
        Thread reader_thread;
        Thread event_thread;

        struct wic_inst inst;
        struct wic_init_arg init_arg;

        Callback<void(bool,const char *, uint16_t)> on_text_cb;
        Callback<void(bool,const void *, uint16_t)> on_binary_cb;
        Callback<void()> on_open_cb;
        Callback<void(uint16_t, const char *, uint16_t)> on_close_cb;

        /* get WICClient instance back from wic_inst */
        static WICClient *to_obj(struct wic_inst *self);

        /* these are all called by wic_inst */
        static void handle_write(struct wic_inst *self, const void *data, size_t size);
        static uint32_t handle_rand(struct wic_inst *self);
        static void handle_open(struct wic_inst *self);
        static void handle_close(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size);
        static void handle_text(struct wic_inst *self, bool fin, const char *data, uint16_t size);
        static void handle_binary(struct wic_inst *self, bool fin, const void *data, uint16_t size);

        /* do_xx are called by the event loop */
        void do_parse();
        void do_open(bool &done, bool &retval);
        void do_close(bool &done);
        void do_close_with_reason(bool &done, uint16_t code, const char *reason, uint16_t size);
        void do_tick();
        void do_send_text(bool &done, bool &retval, bool fin, const char *value, uint16_t size);        
        void do_send_binary(bool &done, bool &retval, bool fin, const void *value, uint16_t size);        
        void do_signal_socket_error(uint16_t code);
        void do_timeout(bool &done);

        /* these run as threads */
        void writer_task(void);
        void reader_task(void);
         
    public:

        WICClient(NetworkInterface &interface);

        /* open a websocket to this url */
        bool open(const char *url);

        /* close an open websocket */
        void close();

        /* send UTF8 text message */
        bool text(const char *value);
        bool text(const char *value, uint16_t len);
        bool text(bool fin, const char *value);
        bool text(bool fin, const char *value, uint16_t len);

        /* send binary message */
        bool binary(const void *value, uint16_t size);
        bool binary(bool fin, const void *value, uint16_t size);

        /* return true if websocket is open */
        bool is_open();

        /* set callback to receive text messages */
        void on_text(Callback<void(bool,const char *, uint16_t)> handler);
        void on_binary(Callback<void(bool,const void *, uint16_t)> handler);
        void on_close(Callback<void(uint16_t,const char *, uint16_t)> handler);
        void on_open(Callback<void()> handler);
};
