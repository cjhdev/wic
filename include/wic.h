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

/* the following reasons will be sent over the wire */

/** the purpose for which the connection was established has been fulfilled */
#define WIC_CLOSE_NORMAL                1000U

/** endpoint is going away */
#define WIC_CLOSE_GOING_AWAY            1001U

/** protocol error */
#define WIC_CLOSE_PROTOCOL_ERROR        1002U

/** endpoint has received an opcode it doesn't support */
#define WIC_CLOSE_UNSUPPORTED           1003U

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

/* the following are not sent over the wire */

#define WIC_CLOSE_RESERVED          1004U

/** abnormal closure #1 (application specific meaning) */
#define WIC_CLOSE_ABNORMAL_1        1005U

/** abnormal closure #2  (application specific meaning) */
#define WIC_CLOSE_ABNORMAL_2        1006U

/** TLS specific abornmal closure  */
#define WIC_CLOSE_TLS               1015U

struct wic_inst;

/** this enum is used to communicate the purpose of the buffer
 *
 * */
enum wic_buffer {

    WIC_BUFFER_HTTP,            /**< handshake */
    WIC_BUFFER_USER,            /**< text or binary */
    WIC_BUFFER_PING,            /**< ping */
    WIC_BUFFER_PONG,            /**< pong (in response to ping) */
    WIC_BUFFER_CLOSE,           /**< close */
    WIC_BUFFER_CLOSE_RESPONSE   /**< close (in response to close) */
};

enum wic_encoding {

    WIC_ENCODING_UTF8,
    WIC_ENCODING_BINARY
};

/** reason for handshake failure
 *
 * */
enum wic_handshake_failure {

    WIC_HANDSHAKE_FAILURE_ABNORMAL_1,   /**< socket closed for reason WIC_CLOSE_ABNORMAL_1 */
    WIC_HANDSHAKE_FAILURE_ABNORMAL_2,   /**< socket closed for reason WIC_CLOSE_ABNORMAL_2 */
    WIC_HANDSHAKE_FAILURE_TLS,          /**< socket closed for some TLS specific reason */
    WIC_HANDSHAKE_FAILURE_IRRELEVANT,   /**< another socket close reason not relevant to this mode */  
    WIC_HANDSHAKE_FAILURE_PROTOCOL,     /**< response was not HTTP as expected */
    WIC_HANDSHAKE_FAILURE_UPGRADE       /**< response did not upgrade to websocket (e.g. perhaps it was a redirect) */
};

/** Binary or UTF8 message received
 *
 * @param[in] inst
 * @param[in] encoding  binary or utf8
 * @param[in] fin       true if the final fragment
 * @param[in] data  
 * @param[in] size      size of data
 *
 * @retval true     message accepted
 * @retval false    host is blocked and cannot receive
 *
 * This function has a return value to indicate if the host was ready
 * to accept the message. If the host returns false the message
 * will remain buffered in wic_inst and will be passed to this function
 * next time wic_parse is called.
 *
 * The behaviour can be used to implement 'back-pressure' on messages received.
 * For example, the host may queue received messages and the queue may
 * become full. In this situation wic should block (i.e. stop parsing
 * new input data) to ensure that messages are not dropped.
 *
 * */
typedef bool (*wic_on_message_fn)(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size);

/** Websocket open event
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

/** Handshake failed event
 *
 * @param[in] inst
 * @param[in] reason
 *
 * */
typedef void (*wic_on_handshake_failure_fn)(struct wic_inst *inst, enum wic_handshake_failure reason);

/** Websocket closed event
 *
 * The websocket was previously open, this message indicates that it is
 * now closed.
 * 
 * @param[in] inst
 * @param[in] code      
 * @param[in] reason    optional UTF8 string explaining the reason for close
 * @param[in] size      size of reason
 *
 * */
typedef void (*wic_on_close_fn)(struct wic_inst *inst, uint16_t code, const char *reason, uint16_t size);

/** Close transport event
 *
 * Use this event to close the underlying transport. 
 *
 * @param[in] inst
 * 
 * */
typedef void (*wic_on_close_transport_fn)(struct wic_inst *inst);

/** Release buffer by sending it.
 *
 * If size is zero, it means WIC is releasing a buffer but not sending
 * anything.
 * 
 * @param[in] inst
 * @param[in] data
 * @param[in] size  size of data (may be zero)
 * @param[in] type  may be used for prioritisation
 *
 * */
typedef void (*wic_on_send_fn)(struct wic_inst *inst, const void *data, size_t size, enum wic_buffer type);

/** Get a buffer of a minimum size for transporting a particular
 * frame type.
 *
 * If WIC does not know the size required, it will set min_size to 0. This
 * means provide the largest buffer. At the moment this only happens
 * during the handshake (i.e. type == WIC_FRAME_TYPE_HTTP).
 *
 * wic_on_send_fn will always be called after this handler. This is
 * this is to provide an opportunity to free any allocates made in this
 * handler.
 * 
 * @param[in] inst
 * @param[in] min_size  buffer should be at least this size
 * @param[in] type      what the memory is used for
 * @param[in] max_size  size of returned memory
 *
 * @return pointer to memory
 *
 * @retval NULL     no memory available for this min_size and type
 *
 * */
typedef void *(*wic_on_buffer_fn)(struct wic_inst *inst, size_t min_size, enum wic_buffer type, size_t *max_size);

/** Called to get a 32bit random number
 *
 * @param[in] inst
 * @return random number
 *
 * */
typedef uint32_t (*wic_rand_fn)(struct wic_inst *inst);

/** A ping was received and WIC responded with a pong
 *
 * @param[in] inst
 *
 * */
typedef void (*wic_on_ping_fn)(struct wic_inst *inst);

/** A pong was received
 *
 * @param[in] inst
 *
 * */
typedef void (*wic_on_pong_fn)(struct wic_inst *inst);

/** An instance is either a client or a server */
enum wic_role {

    WIC_ROLE_CLIENT,    /**< Client role */
    WIC_ROLE_SERVER     /**< Server role */
};

/** URL schema */
enum wic_schema {
    WIC_SCHEMA_HTTP,
    WIC_SCHEMA_HTTPS,
    WIC_SCHEMA_WS,
    WIC_SCHEMA_WSS
};

/** wic_init() argument */
struct wic_init_arg {

    /** Buffer used to store received frame payload and received handshake */
    void *rx;    

    /** Maximum size of rx payload and received handshake */
    size_t rx_max;      

    /** **OPTIONAL** handler called when text or binary is received */
    wic_on_message_fn on_message;

    /** **OPTIONAL** handler called when socket becomes open/established */
    wic_on_open_fn on_open;

    /** **OPTIONAL** handler called when open/established socket becomes closed */
    wic_on_close_fn on_close;

    /** **OPTIONAL** handler called underlying transport should be closed */
    wic_on_close_transport_fn on_close_transport;

    /** **OPTIONAL** handler called when handshake fails */
    wic_on_handshake_failure_fn on_handshake_failure;

    /** **OPTIONAL** handler called when ping is received */
    wic_on_ping_fn on_ping;

    /** **OPTIONAL** handler called when pong is received */
    wic_on_pong_fn on_pong;

    /** **OPTIONAL** handler called to get a random number */
    wic_rand_fn rand;

    /** handler called to write message to transport */
    wic_on_send_fn on_send;

    /** handler called to get a buffer (prior to calling wic_init_arg.on_send) */
    wic_on_buffer_fn on_buffer;

    /** **OPTIONAL** any data you wish to associate with instance */
    void *app;

    /** **OPTIONAL** null-terminated URL required for client role */
    const char *url;

    /** instance can be client or server */
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

enum wic_status {

    WIC_STATUS_SUCCESS,         /**< operation complete successfully */
    WIC_STATUS_NOT_OPEN,        /**< socket is not open */
    WIC_STATUS_TOO_LARGE,       /**< message too large to send */
    WIC_STATUS_WOULD_BLOCK,     /**< buffer not available */
    WIC_STATUS_BAD_STATE,
    WIC_STATUS_BAD_INPUT,
    WIC_STATUS_TIMEOUT
};

/** WIC instance */
struct wic_inst {

    enum wic_role role;

    enum wic_state state;

    struct wic_rx_frame rx;

    wic_on_message_fn on_message;
    
    wic_on_open_fn on_open;
    wic_on_close_fn on_close;
    wic_on_close_transport_fn on_close_transport;
    wic_on_handshake_failure_fn on_handshake_failure;
    
    wic_on_send_fn on_send;
    wic_on_buffer_fn on_buffer;
    
    wic_rand_fn rand;

    wic_on_ping_fn on_ping;
    wic_on_pong_fn on_pong;
    
    void *app;

    const char *url;
    enum wic_schema schema;    
    uint16_t status_code;
    uint16_t port;

    struct wic_header *tx_header;
    enum wic_header_state header_state;

    struct http_parser http;

    enum wic_opcode frag;
    uint16_t pos;
    uint16_t tx_max;

    uint16_t utf8_tx;
    uint16_t utf8_rx;

    uint8_t hash[20U];

    /* The default size should cover all use cases */
    char hostname[WIC_HOSTNAME_MAXLEN];

    const char *redirect_url;
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

/** Get URL schema
 *
 * @param[in] self
 *
 * @return #wic_schema
 *
 * */
enum wic_schema wic_get_url_schema(const struct wic_inst *self);

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
 * @return #wic_status
 *
 * */
enum wic_status wic_start(struct wic_inst *self);

/** Receive data from socket
 *
 * @param[in] self
 * @param[in] data
 * @param[in] size      size of data
 *
 * @return bytes parsed
 *
 * This function will parse one wic frame or message at a time. It is the
 * responsibility of the integrator to track how many bytes have been
 * consumed, and to call wic_parse again to continue parsing.
 *
 * If no bytes are consumed it means that wic_inst is either blocked
 * (see #wic_on_message_fn) or that wic_inst has entered closed state.
 *
 * */
size_t wic_parse(struct wic_inst *self, const void *data, size_t size);

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
 * - #WIC_CLOSE_ABNORMAL_1
 * - #WIC_CLOSE_ABNORMAL_2
 * - #WIC_CLOSE_TLS
 * - #WIC_CLOSE_INVALID_DATA
 * - #WIC_CLOSE_POLICY
 * - #WIC_CLOSE_TOO_BIG
 * - #WIC_CLOSE_EXTENSION_REQUIRED
 * - #WIC_CLOSE_UNEXPECTED_EXCEPTION
 * 
 * */
void wic_close_with_reason(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size);

/**
 * Equivalent to calling wic_send() with WIC_ENCODING_BINARY encoding.
 *
 * */
enum wic_status wic_send_binary(struct wic_inst *self, bool fin, const void *data, uint16_t size);

/**
 * Equivalent to calling wic_send() with WIC_ENCODING_UTF8 encoding.
 *
 * */
enum wic_status wic_send_text(struct wic_inst *self, bool fin, const char *data, uint16_t size);

/** Send a message with either UTF or binary encoding
 *
 * @param[in] self
 * @param[in] encoding  encoding of data
 * @param[in] fin       true if final fragment
 * @param[in] data
 * @param[in] size      size of data
 *
 * @return #wic_status
 *
 * @retval WIC_STATUS_SUCCESS
 * @retval WIC_STATUS_NOT_OPEN
 * @retval WIC_STATUS_WOULD_BLOCK
 * @retval WIC_STATUS_TOO_LARGE    
 *
 * */
enum wic_status wic_send(struct wic_inst *self, enum wic_encoding encoding, bool fin, const char *data, uint16_t size);

/** Send a Ping message
 *
 * A peer will answer a Ping with a Pong. This is useful for implementing
 * a confirmed "keep alive" feature.
 *
 * @param[in] self
 *
 * @return #wic_status
 *
 * @retval WIC_STATUS_SUCCESS
 * @retval WIC_STATUS_NOT_OPEN
 * @retval WIC_STATUS_WOULD_BLOCK
 * @retval WIC_STATUS_TOO_LARGE
 *
 * @see wic_send_ping_with_payload().
 * 
 * */
enum wic_status wic_send_ping(struct wic_inst *self);

/** Send a Ping message with application data
 * 
 * @param[in] self
 * @param[in] data
 * @param[in] size  size of data
 *
 * @return #wic_status
 *
 * @retval WIC_STATUS_SUCCESS
 * @retval WIC_STATUS_NOT_OPEN
 * @retval WIC_STATUS_WOULD_BLOCK
 * @retval WIC_STATUS_TOO_LARGE
 *
 * @see wic_send_ping()
 *
 * */
enum wic_status wic_send_ping_with_payload(struct wic_inst *self, const void *data, uint16_t size);

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
