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

#ifndef WIC_H
#define WIC_H

/** @file */

/**
 * @defgroup wic WIC
 *
 * WIC provides everything needed to turn a TCP/TLS
 * socket into a Websocket.
 *
 * @{
 * 
 * */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "http_parser.h"

#ifdef WIC_PORT_INCLUDE
#   include WIC_PORT_INCLUDE
#else
/** a filename to be included by the preprocessor
 *
 * e.g.
 * 
 * @code
 * -D'WIC_PORT_INCLUDE="port.h"'
 * @endcode
 *
 * */
#   define WIC_PORT_INCLUDE
#   undef  WIC_PORT_INCLUDE
#endif

#ifndef WIC_DEBUG
/** print a debug level message
 *
 * e.g.
 * 
 * @code
 * #define WIC_DEBUG(...) do{printf("debug: ");printf(__VA_ARGS__);printf("\n");}while(0);
 * @endcode
 *
 * */
#   define WIC_DEBUG(...)
#endif

#ifndef WIC_ERROR
/** print an error level message
 *
 * e.g.
 * 
 * @code
 * #define WIC_ERROR(...) do{printf("error: ");printf(__VA_ARGS__);printf("\n");}while(0);
 * @endcode
 *
 * */
#   define WIC_ERROR(...)
#endif

#ifndef WIC_ASSERT
/** assert XX is true
 *
 * e.g.
 *
 * @code
 * #define WIC_ASSERT(XX) assert(XX);
 * @endcode
 *
 * */
#   define WIC_ASSERT(XX)
#endif

#ifndef WIC_HOSTNAME_MAXLEN
/** redefine size of #wic_inst hostname buffer */
#   define WIC_HOSTNAME_MAXLEN 256U
#endif


/** the purpose for which the connection was established has been fulfilled */
#define WIC_CLOSE_NORMAL                1000U
/** endpoint is going away */
#define WIC_CLOSE_GOING_AWAY            1001U
/** protocol error */
#define WIC_CLOSE_PROTOCOL_ERROR        1002U
/** endpoint has received an opcode it doesn't support */
#define WIC_CLOSE_UNSUPPORTED           1003U
#define WIC_CLOSE_RESERVED              1004U
/** no status (not sent over wire) */
#define WIC_CLOSE_NO_STATUS             1005U
/** abnormal closure (not sent over wire) */
#define WIC_CLOSE_ABNORMAL              1006U
/** data received in message not consistent with type of message (e.g. invalid UTF8) */
#define WIC_CLOSE_INVALID_DATA          1007U
/** message received violates endpoint policy */
#define WIC_CLOSE_POLICY                1008U
/** message is too large to receive */
#define WIC_CLOSE_TOO_BIG               1009U
/** extension is required */
#define WIC_CLOSE_EXTENSION_REQUIRED    1010U
/** some other unexpected exception */
#define WIC_CLOSE_UNEXPECTED_EXCEPTION  1011U
/** websocket closed because of a transport layer error (not sent over wire) */
#define WIC_CLOSE_TRANSPORT_ERROR       1012U

struct wic_inst;

/** Called by instance when a text message is receieved
 *
 * @param[in] inst
 * @param[in] fin   true if the final fragment
 * @param[in] data  UTF8
 * @param[in] size  size of data
 *
 * */
typedef void (*wic_on_text_fn)(struct wic_inst *inst, bool fin, const char *data, uint16_t size);

/** Called by instance when a binary message is received
 *
 * @param[in] inst
 * @param[in] fin   true if the final fragment
 * @param[in] data 
 * @param[in] size  size of data
 *
 * */
typedef void (*wic_on_binary_fn)(struct wic_inst *inst, bool fin, const void *data, uint16_t size);

/** Called by instance when websocket is open (client role) or when
 * a handshake has been received (server role).
 *
 * Regardless of role, wic_get_state() called from this handler will
 * return WIC_STATE_READY. This means, among other things, that
 * handshake fields from the peer are accessible.
 *
 * If inst is a server, this handler must call wic_start()
 * in order to send the handshake response and open the websocket.
 *
 * @param[in] inst
 *
 * */
typedef void (*wic_on_open_fn)(struct wic_inst *inst);

/** Called by instance to indicate that websocket is now closed
 *
 * This handler should take care of closing the underlying transport.
 * 
 * @param[in] inst
 * @param[in] code      
 * @param[in] reason    optional UTF8 string explaining the reason for close
 * @param[in] size      size of reason
 *
 * */
typedef void (*wic_on_close_fn)(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);

/** Called by instance to write data to underlying transport
 *
 * @param[in] inst
 * @param[in] data
 * @param[in] size  size of data
 *
 * */
typedef void (*wic_write_fn)(struct wic_inst *inst, const void *data, size_t size);

/** Called by instance to get a 32bit random number
 *
 * @param[in] inst
 * @return random number
 *
 * */
typedef uint32_t (*wic_rand_fn)(struct wic_inst *inst);

/** An instance is either a client or a server */
enum wic_role {

    WIC_ROLE_CLIENT,    /**< Client role */
    WIC_ROLE_SERVER     /**< Server role */
};

/** wic_init() argument */
struct wic_init_arg {

    /** Buffer used to store received frame payload */
    void *rx;    

    /** Maximum size of rx
     *
     * 
     *
     * */
    size_t rx_max;      

    /** Buffer used to assemble frames before writing to transport */
    void *tx;    

    /** Maximum size of tx
     *
     * Recommend that this be no less than (wic_init_arg.rx_max + 4) if you
     * wish to be able to echo a received message.
     * 
     * */
    size_t tx_max;      

    /** **OPTIONAL** pointer to text handler */
    wic_on_text_fn on_text;

    /** **OPTIONAL** pointer to binary handler */
    wic_on_binary_fn on_binary;

    /** **OPTIONAL** pointer to open event handler */
    wic_on_open_fn on_open;

    /** **OPTIONAL** pointer to close event handler */
    wic_on_close_fn on_close;

    /** Pointer to function that writes to transport */
    wic_write_fn write;

    /** **OPTIONAL** pointer to function that returns random */
    wic_rand_fn rand;

    /** **OPTIONAL** pointer to any data you wish to associate with instance */
    void *app;

    /** **OPTIONAL** null-terminate target URL required for client role */
    const char *url;

    /** Instance can be client or server */
    enum wic_role role;
};

enum wic_rx_state {

    WIC_RX_STATE_OPCODE,
    WIC_RX_STATE_SIZE,
    WIC_RX_STATE_SIZE_0,
    WIC_RX_STATE_SIZE_1,
    
    WIC_RX_STATE_SIZE_2,
    WIC_RX_STATE_SIZE_3,
    WIC_RX_STATE_SIZE_4,
    WIC_RX_STATE_SIZE_5,
    WIC_RX_STATE_SIZE_6,
    WIC_RX_STATE_SIZE_7,
    WIC_RX_STATE_SIZE_8,
    WIC_RX_STATE_SIZE_9,
    
    WIC_RX_STATE_MASK_0,
    WIC_RX_STATE_MASK_1,
    WIC_RX_STATE_MASK_2,
    WIC_RX_STATE_MASK_3,
    WIC_RX_STATE_DATA
};

enum wic_opcode {

    WIC_OPCODE_CONTINUE     = 0,
    WIC_OPCODE_TEXT         = 1,
    WIC_OPCODE_BINARY       = 2,
    WIC_OPCODE_RESERVE_3    = 3,
    WIC_OPCODE_RESERVE_4    = 4,
    WIC_OPCODE_RESERVE_5    = 5,
    WIC_OPCODE_RESERVE_6    = 6,
    WIC_OPCODE_RESERVE_7    = 7,
    WIC_OPCODE_CLOSE        = 8,
    WIC_OPCODE_PING         = 9,
    WIC_OPCODE_PONG         = 10,
    WIC_OPCODE_RESERVE_11   = 11,
    WIC_OPCODE_RESERVE_12   = 12,
    WIC_OPCODE_RESERVE_13   = 13,
    WIC_OPCODE_RESERVE_14   = 14,
    WIC_OPCODE_RESERVE_15   = 15
};

struct wic_stream {

    char *write;
    const char *read;
    size_t size;    
    size_t pos;    
    bool error;
};

/** Structure used to link headers with #wic_inst */
struct wic_header {

    struct wic_header *next;
    const char *name;   /**< null-terminated key/name */
    const char *value;  /**< null-terminated value */
};

struct wic_rx_frame {

    bool fin;
    bool rsv1;
    bool rsv2;
    bool rsv3;

    enum wic_opcode opcode;
    enum wic_opcode frag;
    
    uint8_t mask[4U];
    uint64_t size;
    uint16_t pos;
    bool masked;
    
    enum wic_rx_state state;
    uint16_t utf8;

    struct wic_stream s;
};

/** WIC instance state */
enum wic_state {

    WIC_STATE_INIT,             /**< initialised */
    WIC_STATE_PARSE_HANDSHAKE,  /**< parsing http handshake */
    WIC_STATE_READY,            /**< websocket is ready to start */
    WIC_STATE_OPEN,             /**< websocket is open */
    WIC_STATE_CLOSED            /**< websocket is closed */
};

enum wic_header_state {

    WIC_HEADER_STATE_IDLE,
    WIC_HEADER_STATE_FIELD,
    WIC_HEADER_STATE_VALUE
};

/** WIC instance */
struct wic_inst {

    enum wic_role role;

    enum wic_state state;

    struct wic_rx_frame rx;

    struct wic_stream tx;

    wic_on_text_fn on_text;
    wic_on_binary_fn on_binary;
    
    wic_on_open_fn on_open;
    wic_on_close_fn on_close;

    wic_write_fn write;
    wic_rand_fn rand;
    
    void *app;

    const char *url;    
    const char *schema;
    uint16_t status_code;
    uint16_t port;

    struct wic_header *tx_header;
    enum wic_header_state header_state;

    struct http_parser http;

    enum wic_opcode frag;
    uint16_t pos;

    uint16_t utf8_tx;
    uint16_t utf8_rx;

    uint8_t hash[20U];

    /* The default size should cover all use cases */
    char hostname[WIC_HOSTNAME_MAXLEN];
};

/** Initialise an instance
 *
 * @param[in] self
 * @param[in] arg wic_init_arg
 *
 * @retval true     instance has been initialised
 * @retval false    
 *
 * */
bool wic_init(struct wic_inst *self, const struct wic_init_arg *arg);

/** Get pointer to application specific data
 *
 * @param[in] self
 *
 * @return pointer
 * 
 * */
void *wic_get_app(struct wic_inst *self);

/** Get URL string
 * 
 * @param[in] self
 *
 * @return null-terminated URL
 *
 * */
const char *wic_get_url(const struct wic_inst *self);

/** Get status code of handshake
 *
 * @param[in] self
 *
 * @retval 0 status not set
 *
 * */
uint16_t wic_get_status_code(const struct wic_inst *self);

/** Get URL hostname string
 * 
 * @param[in]   self
 *
 * @return null-terminated hostname
 *
 * @retval NULL URL not set
 *
 * */
const char *wic_get_url_hostname(const struct wic_inst *self);

/** Get URL port number
 *
 * @param[in] self
 *
 * @return port number
 *
 * */
uint16_t wic_get_url_port(const struct wic_inst *self);

/** Get URL schema string
 *
 * @param[in] self
 *
 * @return null-terminated URL schema
 *
 * @retval NULL     unknown schema
 *
 * */
const char *wic_get_url_schema(const struct wic_inst *self);

/** Get a redirect URL if the server handshake response was a valid
 * redirect.
 * 
 * @param[in] self
 *
 * @return valid null-terminated URL
 *
 * @retval NULL no redirection URL is available
 *
 * */
const char *wic_get_redirect_url(const struct wic_inst *self);

/** Start instance
 *
 * @param[in] self
 *
 * @retval true     driver started
 * @retval false
 *
 * */
bool wic_start(struct wic_inst *self);

/** Receive data from socket
 *
 * @param[in] self
 * @param[in] data
 * @param[in] size      size of data
 *
 * */
void wic_parse(struct wic_inst *self, const void *data, size_t size);

/** Normal close (1000)
 *
 * @note it is OK to call wic_close() even if already closed
 * 
 * @param[in] self
 *
 * @see wic_close_with_reason()
 *
 * */
void wic_close(struct wic_inst *self);

/** Close with specific code and reason
 *
 * @note it is OK to call close_with_reason() even if already closed
 * 
 * @param[in] self
 * @param[in] code      websocket close code
 * @param[in] reason    UTF8 encoded string
 * @param[in] size      size of reason
 *
 * RFC6455 defines the following codes:
 *
 * - #WIC_CLOSE_NORMAL
 * - #WIC_CLOSE_GOING_AWAY
 * - #WIC_CLOSE_PROTOCOL_ERROR
 * - #WIC_CLOSE_UNSUPPORTED
 * - #WIC_CLOSE_NO_STATUS
 * - #WIC_CLOSE_ABNORMAL
 * - #WIC_CLOSE_INVALID_DATA
 * - #WIC_CLOSE_POLICY
 * - #WIC_CLOSE_TOO_BIG
 * - #WIC_CLOSE_EXTENSION_REQUIRED
 * - #WIC_CLOSE_UNEXPECTED_EXCEPTION
 * - #WIC_CLOSE_TRANSPORT_ERROR
 * 
 * */
void wic_close_with_reason(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size);

/** Send a binary message
 *
 * @param[in] self
 * @param[in] fin   true if final fragment
 * @param[in] data
 * @param[in] size  size of data
 *
 * @retval true     message sent
 * @retval false    
 *
 * */
bool wic_send_binary(struct wic_inst *self, bool fin, const void *data, uint16_t size);

/** Send a text message
 *
 * @param[in] self
 * @param[in] fin   true if final fragment
 * @param[in] data
 * @param[in] size  size of data
 *
 * @retval true     message sent
 * @retval false    
 *
 * */
bool wic_send_text(struct wic_inst *self, bool fin, const char *data, uint16_t size);

/** Send a Ping message
 *
 * A peer will answer a Ping with a Pong. This is useful for implementing
 * a confirmed "keep alive" feature.
 *
 * @param[in] self
 *
 * @retval true     message sent
 * @retval false
 *
 * @see wic_send_ping_with_payload().
 * 
 * */
bool wic_send_ping(struct wic_inst *self);

/** Send a Ping message with application data
 * 
 * @param[in] self
 * @param[in] data
 * @param[in] size  size of data
 *
 * @retval true     message sent
 * @retval false
 *
 * @see wic_send_ping()
 *
 * */
bool wic_send_ping_with_payload(struct wic_inst *self, const void *data, uint16_t size);

/** Send a Pong message
 *
 * A peer will not answer a Pong. This is useful for implementing a
 * non-confirmed "keep alive" feature.
 *
 * @param[in] self
 *
 * @retval true     message sent
 * @retval false 
 *
 * @see wic_send_pong_with_payload().
 * 
 * */
bool wic_send_pong(struct wic_inst *self);

/** Send a Pong message with application data
 *
 * @param[in] self
 * @param[in] data
 * @param[in] size  size of data
 *
 * @retval true     message sent
 * @retval false
 *
 * @see wic_send_pong()
 *
 * */
bool wic_send_pong_with_payload(struct wic_inst *self, const void *data, uint16_t size);

/** Set a header key-value that will be either sent as either:
 *
 * 1. A client handshake request
 * 2. A server handshake response
 *
 * @note wic_get_header() does not return headers previously
 * set by wic_set_header(), it returns headers set by the peer
 *
 * @warning it is the responsibility of the application to ensure header
 * memory remains valid for lifetime of wic_inst
 * 
 * @param[in] self
 * @param[in] header    wic_header
 *
 * @retval true     header linked
 * @retval false    
 * 
 * */
bool wic_set_header(struct wic_inst *self, struct wic_header *header);

/** Get a value for a given header
 *
 * If instance is initialised as a client, this function will get
 * headers sent by the server.
 *
 * If instance is intialised as a server, this function will get
 * headers sent by the client.
 * 
 * @param[in] self
 * @param[in] name  null-terminated key/name
 *
 * @return null-terminated value
 * 
 * */
const char *wic_get_header(const struct wic_inst *self, const char *name);

/** Call successively to get the next header
 *
 * Depends on iterator state within instance. Use wic_rewind_get_next_header()
 * to reset the iterator at any time.
 * 
 * @param[in] self
 * @param[out] name     null-terminated key/name
 *
 * @return null-terminated value
 *
 * @retval NULL     no next header
 *
 * */
const char *wic_get_next_header(struct wic_inst *self, const char **name);

/** Rewind the iterator state used by wic_get_next_header()
 *
 * @param[in] self
 *
 * */
void wic_rewind_get_next_header(struct wic_inst *self);

/** Get instance state
 *
 * @param[in] self
 *
 * @return #wic_state
 *
 * */
enum wic_state wic_get_state(const struct wic_inst *self);

#ifdef __cplusplus
}
#endif

/** @} */

#endif
