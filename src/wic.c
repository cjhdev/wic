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

#include "wic.h"
#include <string.h>
#include <ctype.h>

struct wic_tx_frame {

    bool fin;
    bool rsv1;
    bool rsv2;
    bool rsv3;

    enum wic_opcode opcode;
    enum wic_buffer type;

    uint16_t code;

    bool masked;
    uint8_t mask[4U];

    uint16_t size;
    const void *payload;
};

typedef struct sha1_context
{
    uint32_t total[2];          /* The number of Bytes processed.  */
    uint32_t state[5];          /* The intermediate digest state.  */
    unsigned char buffer[64];   /* The data block being processed. */
    
} sha1_context;

static const enum wic_opcode opcodes[] = {
    WIC_OPCODE_CONTINUE,
    WIC_OPCODE_TEXT,
    WIC_OPCODE_BINARY,
    WIC_OPCODE_RESERVE_3,
    WIC_OPCODE_RESERVE_4,
    WIC_OPCODE_RESERVE_5,
    WIC_OPCODE_RESERVE_6,
    WIC_OPCODE_RESERVE_7,
    WIC_OPCODE_CLOSE,
    WIC_OPCODE_PING,
    WIC_OPCODE_PONG,        
    WIC_OPCODE_RESERVE_11,
    WIC_OPCODE_RESERVE_12,
    WIC_OPCODE_RESERVE_13,
    WIC_OPCODE_RESERVE_14,
    WIC_OPCODE_RESERVE_15        
};

/* static prototypes **************************************************/

static size_t min_frame_size(enum wic_opcode opcode, bool masked, uint16_t payload_size);

static enum wic_status send_pong_with_payload(struct wic_inst *self, const void *data, uint16_t size);
static void close_with_reason(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size, enum wic_buffer type);

static bool allowed_to_send(struct wic_inst *self);

static bool parse_opcode(struct wic_inst *self, struct wic_stream *s);
static bool parse_size(struct wic_inst *self, struct wic_stream *s);
static bool parse_extended_size(struct wic_inst *self, struct wic_stream *s);
static bool parse_mask(struct wic_inst *self, struct wic_stream *s);
static bool parse_data(struct wic_inst *self, struct wic_stream *s);

static enum wic_status start_client(struct wic_inst *self);
static enum wic_status start_server(struct wic_inst *self);

static struct wic_tx_frame *init_mask(struct wic_inst *self, struct wic_tx_frame *f);
static uint8_t opcode_to_byte(enum wic_opcode opcode);
static enum wic_opcode byte_to_opcode(uint8_t b);

static void stream_init(struct wic_stream *self, void *buf, uint32_t size);
static void stream_init_ro(struct wic_stream *self, const void *buf, uint32_t size);
static void stream_rewind(struct wic_stream *self);
static bool stream_read(struct wic_stream *self, void *buf, size_t count);
static bool stream_write(struct wic_stream *self, const void *buf, size_t count);
static enum wic_status stream_put_frame(struct wic_inst *self, struct wic_stream *tx, const struct wic_tx_frame *f);
static bool stream_put_u8(struct wic_stream *self, uint8_t value);
static bool stream_put_u8_masked(struct wic_stream *self, uint8_t value, const uint8_t *mask, uint8_t *unmasked);
static bool stream_put_u16(struct wic_stream *self, uint16_t value);
static bool stream_get_u8(struct wic_stream *self, uint8_t *value);
static bool stream_eof(const struct wic_stream *self);
static bool stream_error(struct wic_stream *self);
static bool stream_put_str(struct wic_stream *self, const char *str);
static size_t stream_max(const struct wic_stream *self);
static size_t stream_pos(const struct wic_stream *self);
static bool stream_seek(struct wic_stream *self, size_t offset);

static bool str_equal(const char *s1, const char *s2);

static char b64_encode_byte(uint8_t in);
static size_t b64_encoded_size(size_t size);
static size_t b64_encode(const void *in, size_t len, char *out, size_t max);

static bool on_message(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size);

static uint16_t utf8_parse(uint16_t state, char in);
static uint16_t utf8_parse_string(uint16_t state, const char *in, uint16_t len);
static bool utf8_is_complete(uint16_t state);
static bool utf8_is_invalid(uint16_t state);

static void server_hash(const char *nonce, size_t len, uint8_t *hash);
static void sha1_init( sha1_context *ctx );
static int sha1_starts_ret( sha1_context *ctx );
static int internal_sha1_process( sha1_context *ctx, const unsigned char data[64] );
static int sha1_update_ret( sha1_context *ctx, const unsigned char *input, size_t ilen );
static int sha1_finish_ret( sha1_context *ctx, unsigned char output[20] );

static int on_header_field(http_parser *http, const char *at, size_t length);
static int on_header_value(http_parser *http, const char *at, size_t length);
static int on_response_complete(http_parser *http);
static int on_request_complete(http_parser *http);

/* functions **********************************************************/

bool wic_init(struct wic_inst *self, const struct wic_init_arg *arg)
{
    struct http_parser_url u;
    size_t i;
    uint16_t port = 0U;

    static const char *supported_schema[] = {
        "http",
        "https",        
        "ws",
        "wss"
    };

    static const enum wic_schema schema_map[] = {
        WIC_SCHEMA_HTTP,
        WIC_SCHEMA_HTTPS,
        WIC_SCHEMA_WS,
        WIC_SCHEMA_WSS
    };

    enum wic_schema schema = WIC_SCHEMA_WS;

    (void)memset(self, 0, sizeof(*self));

    if(arg->on_send == NULL){

        WIC_ERROR("on_send interface is mandatory")
        return false;
    }

    if(arg->on_buffer == NULL){

        WIC_ERROR("on_buffer interface is mandatory")
        return false;
    }

    if((arg->role == WIC_ROLE_CLIENT) && (arg->url == NULL)){

        WIC_ERROR("URL is required for client role")
        return false;
    }

    if(arg->url != NULL){

        if(http_parser_parse_url(arg->url, strlen(arg->url), 0, &u) == 0){

            port = u.port;

            for(i=0; i<sizeof(supported_schema)/sizeof(*supported_schema); i++){

                if(u.field_data[UF_SCHEMA].len == strlen(supported_schema[i])){

                    if(memcmp(&arg->url[u.field_data[UF_SCHEMA].off], supported_schema[i], u.field_data[UF_SCHEMA].len) == 0){

                        schema = schema_map[i];
                        break;
                    }
                }
            }

            if(i == (sizeof(supported_schema)/sizeof(*supported_schema))){

                WIC_ERROR("unrecognised URL schema")
                return false;
            }

            if(u.field_data[UF_HOST].len > (sizeof(self->hostname)-1U)){

                WIC_ERROR("hostname is too long for buffer")
                return false;
            }

            (void)memcpy(self->hostname, &arg->url[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
        }
        else{

            WIC_ERROR("invalid URL")
            return false;
        }
    }

    if(arg->role != WIC_ROLE_CLIENT){

        WIC_ERROR("only supporting client roles")
        return false;
    }

    stream_init(&self->rx.s, arg->rx, arg->rx_max);
    
    self->url = arg->url;
    self->schema = schema;
    self->app = arg->app;
    self->role = arg->role;
    self->port = port;
    
    self->on_message = (arg->on_message != NULL) ? arg->on_message : on_message;    
    self->on_open = arg->on_open;    
    self->on_close = arg->on_close;    

    self->on_send = arg->on_send;
    self->on_buffer = arg->on_buffer;
    self->rand = arg->rand;
    self->on_close_transport = arg->on_close_transport;
    self->on_handshake_failure = arg->on_handshake_failure;
    
    if(self->role == WIC_ROLE_CLIENT){

        http_parser_init(&self->http, HTTP_RESPONSE);
    }
    else{

        self->state = WIC_STATE_PARSE_HANDSHAKE;
        http_parser_init(&self->http, HTTP_REQUEST);
    }

    self->http.data = self;

    return true;
}

const char *wic_get_url(const struct wic_inst *self)
{
    return self->url;
}

const char *wic_get_url_hostname(const struct wic_inst *self)
{    
    return (self->url != NULL) ? self->hostname : NULL;    
}

uint16_t wic_get_status_code(const struct wic_inst *self)
{
    return self->status_code;
}

uint16_t wic_get_url_port(const struct wic_inst *self)
{
    return self->port;
}

enum wic_schema wic_get_url_schema(const struct wic_inst *self)
{
    return self->schema;
}

const char *wic_get_redirect_url(const struct wic_inst *self)
{
    return self->redirect_url;        
}

enum wic_status wic_start(struct wic_inst *self)
{
    enum wic_status retval;

    switch(self->role){
    default:
    case WIC_ROLE_CLIENT:
        retval = start_client(self);
        break;
    case WIC_ROLE_SERVER:
        retval = start_server(self);
        break;
    }

    return retval;
}

void wic_close(struct wic_inst *self)
{
    wic_close_with_reason(self, WIC_CLOSE_NORMAL, NULL, 0U);    
}

void wic_close_with_reason(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size)
{
    close_with_reason(self, code, reason, size, WIC_BUFFER_CLOSE);
}

enum wic_status wic_send_binary(struct wic_inst *self, bool fin, const void *data, uint16_t size)
{
    enum wic_status retval;
    struct wic_stream tx;

    struct wic_tx_frame f = {
        .fin = fin,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = WIC_OPCODE_BINARY,
        .size = size,
        .payload = data,
        .type = WIC_BUFFER_USER
    };

    if(allowed_to_send(self)){

        switch(self->frag){
        case WIC_OPCODE_CONTINUE:
        case WIC_OPCODE_BINARY:

            f.opcode = (self->frag == WIC_OPCODE_BINARY) ? WIC_OPCODE_CONTINUE : f.opcode;

            retval = stream_put_frame(self, &tx, init_mask(self, &f));

            if(retval == WIC_STATUS_SUCCESS){

                self->frag = fin ? WIC_OPCODE_CONTINUE : WIC_OPCODE_BINARY;
                self->on_send(self, tx.read, tx.pos, WIC_BUFFER_USER);
            }                    
            break;

        default:

            WIC_ERROR("text fragmentation already in progress")
            retval = WIC_STATUS_BAD_STATE;            
            break;
        }
    }
    else{

        WIC_ERROR("websocket is not open")
        retval = WIC_STATUS_NOT_OPEN;        
    }

    return retval;
}

enum wic_status wic_send_text(struct wic_inst *self, bool fin, const char *data, uint16_t size)
{
    enum wic_status retval;
    uint16_t state;
    struct wic_stream tx;
    
    struct wic_tx_frame f = {
        .fin = fin,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = WIC_OPCODE_TEXT,
        .size = size,
        .payload = data,
        .type = WIC_BUFFER_USER
    };

    if(allowed_to_send(self)){

        switch(self->frag){
        case WIC_OPCODE_CONTINUE:
        case WIC_OPCODE_TEXT:

            f.opcode = (self->frag == WIC_OPCODE_TEXT) ? WIC_OPCODE_CONTINUE : f.opcode;

            state = utf8_parse_string((self->frag == WIC_OPCODE_CONTINUE) ? 0U : self->utf8_tx, data, size);

            if(utf8_is_invalid(state)){

                WIC_ERROR("payload is not UTF8")
                retval = WIC_STATUS_BAD_INPUT;
            }            
            else if(!fin || utf8_is_complete(state)){

                retval = stream_put_frame(self, &tx, init_mask(self, &f));

                if(retval == WIC_STATUS_SUCCESS){
    
                    self->utf8_tx = state;
                    self->frag = fin ? WIC_OPCODE_CONTINUE : WIC_OPCODE_TEXT;                    
                    self->on_send(self, tx.read, tx.pos, WIC_BUFFER_USER);            
                }                
            }
            else{

                WIC_ERROR("payload is not UTF8")
                retval = WIC_STATUS_BAD_INPUT;
            }
            break;

        default:

            WIC_ERROR("binary fragmentation already in progress")
            retval = WIC_STATUS_BAD_STATE;
            break;
        }
    }
    else{

        WIC_ERROR("websocket is not open")
        retval = WIC_STATUS_NOT_OPEN;
    }

    return retval;
}

enum wic_status wic_send(struct wic_inst *self, enum wic_encoding encoding, bool fin, const char *data, uint16_t size)
{
    enum wic_status retval;

    if(encoding == WIC_ENCODING_BINARY){

        retval = wic_send_binary(self, fin, data, size);
    }
    else{

        retval = wic_send_text(self, fin, data, size);
    }

    return retval;
}

enum wic_status wic_send_ping(struct wic_inst *self)
{
    return wic_send_ping_with_payload(self, NULL, 0U);
}

enum wic_status wic_send_ping_with_payload(struct wic_inst *self, const void *data, uint16_t size)
{   
    enum wic_status retval;
    struct wic_stream tx;

    struct wic_tx_frame f = {
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = WIC_OPCODE_PING,
        .size = size,
        .payload = data,
        .type = WIC_BUFFER_PING
    };

    if(allowed_to_send(self)){

        retval = stream_put_frame(self, &tx, init_mask(self, &f));

        if(retval == WIC_STATUS_SUCCESS){

            self->on_send(self, tx.read, tx.pos, WIC_BUFFER_PING);
        }        
    }
    else{

        WIC_ERROR("websocket is not open")
        retval = WIC_STATUS_NOT_OPEN;
    }

    return retval;
}

size_t wic_parse(struct wic_inst *self, const void *data, size_t size)
{
    size_t bytes;
    http_parser_settings settings;
    struct wic_stream s;
    bool blocked = false;

    stream_init_ro(&s, data, size);            

    if(self->state == WIC_STATE_PARSE_HANDSHAKE){
    
        http_parser_settings_init(&settings);

        settings.on_header_field = on_header_field;
        settings.on_header_value = on_header_value;
        settings.on_message_complete = (self->role == WIC_ROLE_CLIENT) ? on_response_complete : on_request_complete;
        
        bytes = http_parser_execute(&self->http, &settings, (char *)data, size);

        (void)stream_seek(&s, bytes);

        if(self->http.http_errno != 0U){

            WIC_ERROR("http parser reports error: (%u %s) %s", self->http.http_errno, http_errno_name(self->http.http_errno), http_errno_description(self->http.http_errno))

            if(self->on_close_transport != NULL){

                self->on_close_transport(self);
            }

            if(self->on_handshake_failure != NULL){

                if(self->http.http_errno == HPE_CB_message_complete){

                    self->on_handshake_failure(self, WIC_HANDSHAKE_FAILURE_UPGRADE);
                }
                else{

                    self->on_handshake_failure(self, WIC_HANDSHAKE_FAILURE_PROTOCOL);
                }
            }

            self->state = WIC_STATE_CLOSED;
        }
        else if(self->state == WIC_STATE_READY){

            if(self->on_open != NULL){

                self->on_open(self);
            }

            self->state = WIC_STATE_OPEN;
        }        
        else{

            /* still parsing... */
        }
    }

    /* parse websocket */
    if(self->state == WIC_STATE_OPEN){

        do{
            switch(self->rx.state){
            case WIC_RX_STATE_OPCODE:

                blocked = parse_opcode(self, &s);
                break;

            case WIC_RX_STATE_SIZE:

                blocked = parse_size(self, &s);
                break;

            case WIC_RX_STATE_SIZE_0:
            case WIC_RX_STATE_SIZE_1:
            case WIC_RX_STATE_SIZE_2:
            case WIC_RX_STATE_SIZE_3:
            case WIC_RX_STATE_SIZE_4:
            case WIC_RX_STATE_SIZE_5:
            case WIC_RX_STATE_SIZE_6:
            case WIC_RX_STATE_SIZE_7:
            case WIC_RX_STATE_SIZE_8:
            case WIC_RX_STATE_SIZE_9:

                blocked = parse_extended_size(self, &s);
                break;
            
            case WIC_RX_STATE_MASK_0:
            case WIC_RX_STATE_MASK_1:
            case WIC_RX_STATE_MASK_2:
            case WIC_RX_STATE_MASK_3:

                blocked = parse_mask(self, &s);
                break;

            default:
                break;
            }

            switch(self->rx.state){
            case WIC_RX_STATE_DATA:

                blocked = parse_data(self, &s);
                break;

            default:
                break;
            }
        }
        while(!blocked && (self->state == WIC_STATE_OPEN));
    }

    /* consume all bytes if not open
     * to clear buffers and so on */
    return (self->state == WIC_STATE_OPEN) ? stream_pos(&s) : size;    
}

void *wic_get_app(struct wic_inst *self)
{
    return self->app;
}

const char *wic_get_header(const struct wic_inst *self, const char *name)
{
    const char *retval = NULL;
    size_t pos = 0U;

    if(self->state == WIC_STATE_READY){

        while(pos < self->rx.s.pos){
    
            if(str_equal(&self->rx.s.read[pos], name)){

                pos += strlen(&self->rx.s.read[pos]);
                pos++;
                retval = &self->rx.s.read[pos];
                break;
            }
            else{

                pos += strlen(&self->rx.s.read[pos]);
                pos++;

                WIC_ASSERT((self->rx.s.pos-pos) > 0U)

                pos += strlen(&self->rx.s.read[pos]);
                pos++;                
            }
        }
    }
    else{

        WIC_DEBUG("headers not available in this state")
    }

    return retval;
}

void wic_rewind_get_next_header(struct wic_inst *self)
{
    self->pos = 0U;
}

const char *wic_get_next_header(struct wic_inst *self, const char **name)
{
    const char *retval = NULL;

    *name = NULL;

    if(self->pos < self->rx.s.pos){

        *name = &self->rx.s.read[self->pos];
        
        self->pos += strlen(&self->rx.s.read[self->pos]);
        self->pos++;

        WIC_ASSERT((self->rx.s.pos-self->pos) > 0U)

        retval = &self->rx.s.read[self->pos];
        
        self->pos += strlen(&self->rx.s.read[self->pos]);
        self->pos++;
    }

    return retval;
}

bool wic_set_header(struct wic_inst *self, struct wic_header *header)
{
    bool retval = false;

    if((header->name != NULL) && (header->value != NULL)){

        header->next = self->tx_header;
        self->tx_header = header;
        retval = true;
    }

    return retval;
}

enum wic_state wic_get_state(const struct wic_inst *self)
{
    return self->state;
}

/* static functions ***************************************************/

static size_t min_frame_size(enum wic_opcode opcode, bool masked, uint16_t payload_size)
{
    size_t retval = payload_size;

    if(opcode == WIC_OPCODE_CLOSE){

        /* close includes 2 byte code */
        retval += 2U;
    }

    if(retval > 125U){

        /* size encoding up to 65535 bytes */
        retval += 2UL;
    }

    /* header */
    retval += 2UL;

    if(masked){

        retval += 4UL;
    }
    
    return retval;
}

static enum wic_status send_pong_with_payload(struct wic_inst *self, const void *data, uint16_t size)
{
    enum wic_status retval;
    struct wic_stream tx;
    
    struct wic_tx_frame f = {
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = WIC_OPCODE_PONG,
        .size = size,
        .payload = data,
        .type = WIC_BUFFER_PONG
    };

    if(allowed_to_send(self)){

        retval = stream_put_frame(self, &tx, init_mask(self, &f));

        if(retval == WIC_STATUS_SUCCESS){

            self->on_send(self, tx.read, tx.pos, f.type);
        }        
    }
    else{

        WIC_ERROR("websocket is not open")
        retval = WIC_STATUS_NOT_OPEN;
    }
    
    return retval;
}

static void close_with_reason(struct wic_inst *self, uint16_t code, const char *reason, uint16_t size, enum wic_buffer type)
{
    struct wic_stream tx;
    
    struct wic_tx_frame f = {
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = WIC_OPCODE_CLOSE,
        .payload = reason,
        .code = code,
        .size = size,
        .type = type
    };

    switch(self->state){
    case WIC_STATE_INIT:
        self->state = WIC_STATE_CLOSED;
        break;
    case WIC_STATE_CLOSED:
        break;
    case WIC_STATE_PARSE_HANDSHAKE:

        self->state = WIC_STATE_CLOSED;

        if(self->on_close_transport != NULL){

            self->on_close_transport(self);
        }        

        if(self->on_handshake_failure != NULL){

            switch(code){
            case WIC_CLOSE_ABNORMAL_1:
                self->on_handshake_failure(self, WIC_HANDSHAKE_FAILURE_ABNORMAL_1);
                break;
            case WIC_CLOSE_ABNORMAL_2:
                self->on_handshake_failure(self, WIC_HANDSHAKE_FAILURE_ABNORMAL_2);
                break;
            case WIC_CLOSE_TLS:
                self->on_handshake_failure(self, WIC_HANDSHAKE_FAILURE_TLS);
                break;
            default:
                self->on_handshake_failure(self, WIC_HANDSHAKE_FAILURE_IRRELEVANT);
                break;            
            }
        }
        break;
        
    case WIC_STATE_OPEN:
    case WIC_STATE_READY:
    
        self->state = WIC_STATE_CLOSED;

        if(!utf8_is_complete(utf8_parse_string(0U, reason, size))){

            WIC_ERROR("reason string must be UTF8 (discarding)")
            f.size = 0U;
            f.payload = NULL;
        }

        switch(code){
        /* these are not written */
        case WIC_CLOSE_ABNORMAL_1:
        case WIC_CLOSE_ABNORMAL_2:
        case WIC_CLOSE_TLS:
            break;
        default:
        
            if(stream_put_frame(self, &tx, init_mask(self, &f)) == WIC_STATUS_SUCCESS){
                
                self->on_send(self, tx.read, tx.pos, type);
            }
            break;
        }
         
        if(self->on_close_transport != NULL){

            self->on_close_transport(self);
        }
        
        if(self->on_close != NULL){

            self->on_close(self, code, reason, size);
        }        
    }    
}

static bool allowed_to_send(struct wic_inst *self)
{
    if((self->role == WIC_ROLE_CLIENT) && (self->state == WIC_STATE_READY)){

        self->state = WIC_STATE_OPEN;
    }
    
    return (self->state == WIC_STATE_OPEN);
}

static bool parse_opcode(struct wic_inst *self, struct wic_stream *s)
{
    uint8_t b;
    bool blocked = false;
    
    if(stream_get_u8(s, &b)){

        stream_rewind(&self->rx.s);

        self->rx.fin = ((b & 0x80U) != 0U);
        self->rx.rsv1 = ((b & 0x40U) != 0U);
        self->rx.rsv2 = ((b & 0x20U) != 0U);
        self->rx.rsv3 = ((b & 0x10U) != 0U);

        self->rx.utf8 = 0U;

        /* no extensions atm so these must be 0 */
        if(self->rx.rsv1 || self->rx.rsv2 || self->rx.rsv3){

            close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
        }
        else{

            self->rx.opcode = byte_to_opcode(b);

            /* filter opcodes */
            switch(self->rx.opcode){
            case WIC_OPCODE_CLOSE:
            case WIC_OPCODE_PING:
            case WIC_OPCODE_PONG:

                /* close, ping, and pong must be final */
                if(!self->rx.fin){
                    
                    close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
                }
                break;

            case WIC_OPCODE_CONTINUE:

                /* continue must follow a non-final text/binary */
                if(self->rx.frag == WIC_OPCODE_CONTINUE){

                    close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
                }
                else{

                    self->rx.utf8 = self->utf8_rx;
                }
                break;

            case WIC_OPCODE_TEXT:
            case WIC_OPCODE_BINARY:

                /* interrupting fragmentation */
                if(self->rx.frag != WIC_OPCODE_CONTINUE){

                    close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
                }
                break;
                
            default:
                close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
                break;
            }

            self->rx.state = WIC_RX_STATE_SIZE;
        }
    }
    else{

        blocked = true;
    }

    return blocked;
}

static bool parse_size(struct wic_inst *self, struct wic_stream *s)
{
    bool blocked = false;
    uint8_t b;

    if(stream_get_u8(s, &b)){

        self->rx.masked = ((b & 0x80U) != 0U);
        self->rx.size = b & 0x7fU;

        switch(self->rx.opcode){
        case WIC_OPCODE_CLOSE:

            if((self->rx.size > 125U) || (self->rx.size == 1U)){

                close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
            }
            else{

                if(self->rx.size == 0U){

                    close_with_reason(self, WIC_CLOSE_NORMAL, NULL, 0U, WIC_BUFFER_CLOSE);
                }
                else if(self->rx.size > stream_max(&self->rx.s)){

                    close_with_reason(self, WIC_CLOSE_TOO_BIG, NULL, 0U, WIC_BUFFER_CLOSE);
                }
                else{

                    /* nothing */
                }                    
            }
            break;
        
        case WIC_OPCODE_PING:
        case WIC_OPCODE_PONG:
        
            if(self->rx.size > 125U){
                
                close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE);
            }
            else if(self->rx.size > stream_max(&self->rx.s)){

                close_with_reason(self, WIC_CLOSE_TOO_BIG, NULL, 0U, WIC_BUFFER_CLOSE);
            }
            else{

                /* nothing */
            }
            break;

        default:
            break;
        }

        switch(self->rx.size){
        case 127U:
            self->rx.state = WIC_RX_STATE_SIZE_2;
            self->rx.size = 0U;
            break;
        case 126U:
            self->rx.state = WIC_RX_STATE_SIZE_0;
            self->rx.size = 0U;
            break;
        default:
            self->rx.state = self->rx.masked ? WIC_RX_STATE_MASK_0 : WIC_RX_STATE_DATA;                        
            break;            
        }                
    }
    else{

        blocked = true;
    }

    return blocked;
}

static bool parse_extended_size(struct wic_inst *self, struct wic_stream *s)
{
    uint8_t b;
    bool blocked = false;

    if(stream_get_u8(s, &b)){

        self->rx.size <<= 8;
        self->rx.size |= b;

        switch(self->rx.state){
        default:
        case WIC_RX_STATE_SIZE_0:
            self->rx.state = WIC_RX_STATE_SIZE_1;
            break;
        case WIC_RX_STATE_SIZE_2:
            self->rx.state = WIC_RX_STATE_SIZE_3;
            break;
        case WIC_RX_STATE_SIZE_3:
            self->rx.state = WIC_RX_STATE_SIZE_4;
            break;
        case WIC_RX_STATE_SIZE_4:
            self->rx.state = WIC_RX_STATE_SIZE_5;
            break;
        case WIC_RX_STATE_SIZE_5:
            self->rx.state = WIC_RX_STATE_SIZE_6;
            break;
        case WIC_RX_STATE_SIZE_6:
            self->rx.state = WIC_RX_STATE_SIZE_7;
            break;
        case WIC_RX_STATE_SIZE_7:
            self->rx.state = WIC_RX_STATE_SIZE_8;
            break;
        case WIC_RX_STATE_SIZE_8:
            self->rx.state = WIC_RX_STATE_SIZE_9;
            break;
        case WIC_RX_STATE_SIZE_1:
        case WIC_RX_STATE_SIZE_9:            
            self->rx.state = self->rx.masked ? WIC_RX_STATE_MASK_0 : WIC_RX_STATE_DATA;
            break;
        }
    }
    else{

        blocked = true;
    }

    return blocked;
}

static bool parse_mask(struct wic_inst *self, struct wic_stream *s)
{
    bool blocked;
    uint8_t b;

    if(stream_get_u8(s, &b)){

        self->rx.mask[self->rx.state - WIC_RX_STATE_MASK_0] = b;
        
        switch(self->rx.state){
        default:
        case WIC_RX_STATE_MASK_0:
            self->rx.state = WIC_RX_STATE_MASK_1;
            break;
        case WIC_RX_STATE_MASK_1:
            self->rx.state = WIC_RX_STATE_MASK_2;
            break;
        case WIC_RX_STATE_MASK_2:
            self->rx.state = WIC_RX_STATE_MASK_3;
            break;
        case WIC_RX_STATE_MASK_3:
            self->rx.state = WIC_RX_STATE_DATA;
            break;
        }                    
    }
    else{

        blocked = true;
    }

    return blocked;
}

static bool parse_data(struct wic_inst *self, struct wic_stream *s)
{
    uint16_t code;
    uint8_t b;
    bool blocked = false;

    /* if still receiving data part */
    if(self->rx.size > 0U){

        /* no more space in rx buffer and so pass to the user as a fragment */
        if(stream_eof(&self->rx.s)){

            switch((self->rx.opcode == WIC_OPCODE_CONTINUE) ? self->rx.frag : self->rx.opcode){
            case WIC_OPCODE_TEXT:
                blocked = !self->on_message(self, WIC_ENCODING_UTF8, false, self->rx.s.read, self->rx.s.pos);
                break;
            case WIC_OPCODE_BINARY:
                blocked = !self->on_message(self, WIC_ENCODING_BINARY, false, self->rx.s.read, self->rx.s.pos);
                break;                
            default:
                break;
            }

            if(!blocked){

                stream_rewind(&self->rx.s);
            }
        }
        else{

            if(stream_get_u8(s, &b)){

                self->rx.size--;

                if(self->rx.masked){

                    stream_put_u8_masked(&self->rx.s, b, self->rx.mask, &b);
                }
                else{

                    stream_put_u8(&self->rx.s, b);
                }

                switch((self->rx.opcode == WIC_OPCODE_CONTINUE) ? self->rx.frag : self->rx.opcode){
                case WIC_OPCODE_TEXT:

                    self->rx.utf8 = utf8_parse(self->rx.utf8, (char)b);

                    if(utf8_is_invalid(self->rx.utf8)){

                        close_with_reason(self, WIC_CLOSE_INVALID_DATA, NULL, 0U, WIC_BUFFER_CLOSE);
                    }
                    break;

                case WIC_OPCODE_CLOSE:

                    if(stream_pos(&self->rx.s) > 2U){

                        self->rx.utf8 = utf8_parse(self->rx.utf8, (char)b);

                        if(utf8_is_invalid(self->rx.utf8)){

                            close_with_reason(self, WIC_CLOSE_INVALID_DATA, NULL, 0U, WIC_BUFFER_CLOSE_RESPONSE);
                        }
                    }
                    break;
                        
                default:
                    break;
                }
            }
            else{

                blocked = true;
            }
        }
    }

    /* finished reading data part */
    if((self->state == WIC_STATE_OPEN) && (self->rx.size == 0U)){

        enum wic_opcode opcode = (self->rx.opcode == WIC_OPCODE_CONTINUE) ? self->rx.frag : self->rx.opcode;

        switch(opcode){
        case WIC_OPCODE_TEXT:

            if(!self->rx.fin){

                if(self->on_message(self, WIC_ENCODING_UTF8, self->rx.fin, self->rx.s.read, self->rx.s.pos)){

                    self->rx.frag = opcode;
                    self->utf8_rx = self->rx.utf8;
                }
                else{

                    blocked = true;
                }
            }
            else if(utf8_is_complete(self->rx.utf8)){

                if(self->on_message(self, WIC_ENCODING_UTF8, self->rx.fin, self->rx.s.read, self->rx.s.pos)){
                    
                    self->rx.frag = WIC_OPCODE_CONTINUE;
                }
                else{

                    blocked = true;
                }
            }
            else{

                close_with_reason(self, WIC_CLOSE_INVALID_DATA, NULL, 0U, WIC_BUFFER_CLOSE);
            }
            break;

        case WIC_OPCODE_BINARY:

            if(self->on_message(self, WIC_ENCODING_BINARY, self->rx.fin, self->rx.s.read, self->rx.s.pos)){

                self->rx.frag = self->rx.fin ? WIC_OPCODE_CONTINUE : opcode;
            }
            else{

                blocked = true;
            }
            break;
        
        case WIC_OPCODE_CLOSE:

            code = (uint8_t)self->rx.s.read[0];
            code <<= 8;
            code |= (uint8_t)self->rx.s.read[1];

            switch(code){
            case WIC_CLOSE_NORMAL:
            case WIC_CLOSE_GOING_AWAY:
            case WIC_CLOSE_PROTOCOL_ERROR:
            case WIC_CLOSE_UNSUPPORTED:
            case WIC_CLOSE_INVALID_DATA:
            case WIC_CLOSE_POLICY:
            case WIC_CLOSE_TOO_BIG:
            case WIC_CLOSE_EXTENSION_REQUIRED:
            case WIC_CLOSE_UNEXPECTED_EXCEPTION:

                if(utf8_is_complete(self->rx.utf8)){

                    close_with_reason(self, code, &self->rx.s.read[sizeof(code)], self->rx.s.pos - sizeof(code), WIC_BUFFER_CLOSE_RESPONSE);
                }
                else{

                    close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE_RESPONSE);
                }
                break;

            default:

                if((code >= 3000U) && (code <= 3999)){

                    close_with_reason(self, WIC_CLOSE_NORMAL, NULL, 0U, WIC_BUFFER_CLOSE_RESPONSE);
                }
                else if((code >= 4000U) && (code <= 4999)){

                    close_with_reason(self, WIC_CLOSE_NORMAL, NULL, 0U, WIC_BUFFER_CLOSE_RESPONSE);
                }
                else{
                    
                    close_with_reason(self, WIC_CLOSE_PROTOCOL_ERROR, NULL, 0U, WIC_BUFFER_CLOSE_RESPONSE);
                }
                break;
            }
                
            break;

        case WIC_OPCODE_PING:

            send_pong_with_payload(self, self->rx.s.read, self->rx.s.pos);

            if(self->on_ping != NULL){

                self->on_ping(self);
            }                
            break;
        
        case WIC_OPCODE_PONG:

            if(self->on_pong != NULL){

                self->on_pong(self);
            }
            break;
        
        default:
            break;
        }

        if(!blocked){
            
            self->rx.state = WIC_RX_STATE_OPCODE;
        }                
    }

    return blocked;        
}

static enum wic_status start_server(struct wic_inst *self)
{
    void *buf;
    size_t max;
    struct wic_stream tx;
    enum wic_status retval;
    char b64_hash[28U];

    if(self->state == WIC_STATE_READY){

        buf = self->on_buffer(self, 0U, WIC_BUFFER_HTTP, &max);

        if(buf != NULL){

            stream_init(&tx, buf, max);

            stream_put_str(&tx, "HTTP/1.1 101 Switching Protocols\r\n");

            stream_put_str(&tx, "Upgrade: websocket\r\n");
            stream_put_str(&tx, "Connection: upgrade\r\n");

            stream_put_str(&tx, "Sec-WebSocket-Accept: ");

            b64_encode(self->hash, sizeof(self->hash), b64_hash, sizeof(b64_hash));
            stream_write(&tx, b64_hash, sizeof(b64_hash));
            stream_put_str(&tx, "\r\n");

            for(struct wic_header *ptr = self->tx_header; ptr != NULL; ptr = ptr->next){

                stream_put_str(&tx, ptr->name);
                stream_put_str(&tx, ": ");
                stream_put_str(&tx, ptr->value);
                stream_put_str(&tx, "\r\n");
            }
            
            stream_put_str(&tx, "\r\n");

            if(!stream_error(&tx)){

                self->state = WIC_STATE_OPEN;
                self->on_send(self, tx.read, tx.pos, WIC_BUFFER_HTTP);
                retval = WIC_STATUS_SUCCESS;           
            }
            else{

                /* send with length zero to free */
                self->on_send(self, tx.read, 0U, WIC_BUFFER_HTTP);
                WIC_DEBUG("handshake too large for buffer")
                retval = WIC_STATUS_TOO_LARGE;
            }
        }
        else{

            WIC_DEBUG("buffer not available")
            retval = WIC_STATUS_WOULD_BLOCK;
        }        
    }
    else{

        WIC_DEBUG("server wic_inst.state must be WIC_STATE_READY to start")
        retval = WIC_STATUS_BAD_STATE;
    }

    return retval;
}

static enum wic_status start_client(struct wic_inst *self)
{
    void *buf;
    size_t max;
    struct wic_stream tx;
    struct http_parser_url u;
    enum wic_status retval;
    uint32_t nonce[4U];
    char nonce_b64[24U];

    WIC_ASSERT(sizeof(nonce_b64) == b64_encoded_size(sizeof(nonce)))

    if(self->state == WIC_STATE_INIT){

        http_parser_url_init(&u);

        if(http_parser_parse_url(self->url, strlen(self->url), 0, &u) == 0){

            buf = self->on_buffer(self, 0U, WIC_BUFFER_HTTP, &max);

            if(buf != NULL){

                stream_init(&tx, buf, max);
    
                stream_put_str(&tx, "GET ");
                stream_write(&tx, &self->url[u.field_data[UF_PATH].off], u.field_data[UF_PATH].len);
                if(u.field_data[UF_QUERY].len > 0){
                    stream_put_str(&tx, "?");
                    stream_write(&tx, &self->url[u.field_data[UF_QUERY].off], u.field_data[UF_QUERY].len);
                }
                if(u.field_data[UF_FRAGMENT].len > 0){
                    stream_put_str(&tx, "#");
                    stream_write(&tx, &self->url[u.field_data[UF_FRAGMENT].off], u.field_data[UF_FRAGMENT].len);
                }
                stream_put_str(&tx, " HTTP/1.1\r\n");

                stream_put_str(&tx, "Host: ");
                stream_write(&tx, &self->url[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
                if(u.port != 0U){

                    stream_put_str(&tx, ":");
                    stream_write(&tx, &self->url[u.field_data[UF_PORT].off], u.field_data[UF_PORT].len);
                }
                stream_put_str(&tx, "\r\n");

                stream_put_str(&tx, "Upgrade: websocket\r\n");
                stream_put_str(&tx, "Connection: upgrade\r\n");
                stream_put_str(&tx, "Sec-WebSocket-Version: 13\r\n");

                if(self->rand != NULL){

                    nonce[0] = self->rand(self);
                    nonce[1] = self->rand(self);
                    nonce[2] = self->rand(self);
                    nonce[3] = self->rand(self);
                }
                else{

                    (void)memset(nonce, 0xaa, sizeof(nonce));
                }

                (void)b64_encode(nonce, sizeof(nonce), nonce_b64, sizeof(nonce_b64));
                
                server_hash(nonce_b64, sizeof(nonce_b64), self->hash);

                stream_put_str(&tx, "Sec-WebSocket-Key: ");
                stream_write(&tx, nonce_b64, sizeof(nonce_b64));            
                stream_put_str(&tx, "\r\n");

                for(struct wic_header *ptr = self->tx_header; ptr != NULL; ptr = ptr->next){

                    stream_put_str(&tx, ptr->name);
                    stream_put_str(&tx, ": ");
                    stream_put_str(&tx, ptr->value);
                    stream_put_str(&tx, "\r\n");
                }

                stream_put_str(&tx, "\r\n");

                if(!stream_error(&tx)){

                    self->state = WIC_STATE_PARSE_HANDSHAKE;
                    self->on_send(self, tx.read, tx.pos, WIC_BUFFER_HTTP);

                    retval = WIC_STATUS_SUCCESS;  
                }
                else{

                    /* send with length zero to free */
                    self->on_send(self, tx.read, 0U, WIC_BUFFER_HTTP);

                    WIC_ERROR("handshake too large for buffer")
                    retval = WIC_STATUS_TOO_LARGE;
                }
            }
            else{

                WIC_ERROR("no buffer available")
                retval = WIC_STATUS_WOULD_BLOCK;
            }
        }
        else{

            WIC_ERROR("URL is invalid")
            retval = WIC_STATUS_BAD_INPUT;
        }           
    }
    else{

        WIC_ERROR("client wic_inst.state must be WIC_STATE_INIT to start")
        retval = WIC_STATUS_BAD_STATE;
    }

    return retval;
}

static struct wic_tx_frame *init_mask(struct wic_inst *self, struct wic_tx_frame *f)
{
    uint32_t mask = (self->rand != NULL) ? self->rand(self) : 0xaaaaaaaaUL;

    /* so, I feel the mask should be left out if there is no data but
     * this causes autobahn suite to fail */
    f->masked = (self->role == WIC_ROLE_CLIENT);

    (void)memcpy(f->mask, &mask, sizeof(f->mask));
    
    return f;
}

static uint8_t opcode_to_byte(enum wic_opcode opcode)
{
    return (uint8_t)opcode;
}

static enum wic_opcode byte_to_opcode(uint8_t b)
{
    return opcodes[b & 0xfU];
}

static void stream_init(struct wic_stream *self, void *buf, uint32_t size)
{
    self->write = buf;
    self->read = buf;
    self->size = size;
    self->pos = 0U;
    self->error = false;
}

static void stream_init_ro(struct wic_stream *self, const void *buf, uint32_t size)
{
    self->write = NULL;
    self->read = buf;
    self->size = size;
    self->pos = 0U;
    self->error = false;
}

static void stream_rewind(struct wic_stream *self)
{
    self->pos = 0U;
    self->error = false;
}

static bool stream_read(struct wic_stream *self, void *buf, size_t count)
{
    bool retval = false;
    
    if(!self->error){
    
        if((self->size - self->pos) >= count){

            (void)memcpy(buf, &self->read[self->pos], count);
            self->pos += count;
            retval = true;
        }    
        else{
            
            self->error = true;
        }
    }
    
    return retval;
}

static bool stream_write(struct wic_stream *self, const void *buf, size_t count)
{
    bool retval = false;
    
    if(self->write != NULL){
        
        if(!self->error){
        
            if((self->size - self->pos) >= count){

                if(count > 0U){

                    (void)memcpy(&self->write[self->pos], buf, count);
                }

                self->pos += count;
                retval = true;
            }
            else{
                
                self->error = true;
            }
        }
    }
    
    return retval;
}

static enum wic_status stream_put_frame(struct wic_inst *self, struct wic_stream *tx, const struct wic_tx_frame *f)
{
    enum wic_status retval;
    void *buf;
    size_t payload_size;
    size_t frame_size;
    size_t max;
    
    payload_size = f->size + ((f->opcode == WIC_OPCODE_CLOSE) ? 2U : 0U);
    frame_size = min_frame_size(f->opcode, f->masked, f->size);

    buf = self->on_buffer(self, frame_size, f->type, &max);

    /* the max arguemnt will always be returned to indicate the maximum
     * possible size of this buffer type if the call succeeded.
     *
     * This is necessary because we don't want to block expecting a
     * buffer that will never be allocated.
     *
     * */
    if(max >= frame_size){

        if(buf != NULL){

            stream_init(tx, buf, frame_size);
            
            stream_put_u8(tx, (f->fin ? 0x80U : 0U )
                | (f->rsv1 ? 0x40U : 0U )
                | (f->rsv2 ? 0x20U : 0U )
                | (f->rsv3 ? 0x10U : 0U )
                | opcode_to_byte(f->opcode)
            );

            if(payload_size <= 125U){

                stream_put_u8(tx, (f->masked ? 0x80U : 0U) | payload_size);
            }
            else{

                stream_put_u8(tx, (f->masked ? 0x80U : 0U) | 126U);
                stream_put_u16(tx, payload_size);        
            }

            if(f->masked){

                stream_write(tx, f->mask, sizeof(f->mask));

                size_t pos;
                const uint8_t *ptr = f->payload;

                if(f->opcode == WIC_OPCODE_CLOSE){

                    stream_put_u8(tx, (f->code >> 8) ^ f->mask[0]);                
                    stream_put_u8(tx, f->code ^ f->mask[1]);

                    for(pos=0U; pos < f->size; pos++){

                        stream_put_u8(tx, ptr[pos] ^ f->mask[(pos+2U) % 4]);                
                    }        
                }
                else{

                    for(pos=0U; pos < payload_size; pos++){

                        stream_put_u8(tx, ptr[pos] ^ f->mask[pos % 4]);                
                    }        
                }
            }    
            else{

                if(f->opcode == WIC_OPCODE_CLOSE){

                    stream_put_u8(tx, f->code >> 8);                
                    stream_put_u8(tx, f->code);
                }
                
                stream_write(tx, f->payload, payload_size);        
            }

            retval = stream_error(tx) ? WIC_STATUS_WOULD_BLOCK : WIC_STATUS_SUCCESS;
        }
        else{

            WIC_ERROR("no buffer available")
            retval = WIC_STATUS_WOULD_BLOCK;
        }
    }
    else{

        WIC_ERROR("message too large for buffer")
        retval = WIC_STATUS_TOO_LARGE;
    }

    return retval;
}

static size_t stream_max(const struct wic_stream *self)
{
    return self->size;
}

static size_t stream_pos(const struct wic_stream *self)
{
    return self->pos;
}

static bool stream_seek(struct wic_stream *self, size_t offset)
{
    bool retval = false;

    if(self->size >= offset){

        self->pos = offset;        
        retval = true;
    }

    return retval;
}

static bool stream_eof(const struct wic_stream *self)
{
    return self->pos == self->size;
}

static bool stream_put_u8(struct wic_stream *self, uint8_t value)
{
    return stream_write(self, &value, sizeof(value));
}

static bool stream_put_u16(struct wic_stream *self, uint16_t value)
{
    uint8_t out[] = {
        value >> 8,
        value
    };
    
    return stream_write(self, out, sizeof(out));
}

static bool stream_get_u8(struct wic_stream *self, uint8_t *value)
{
    return stream_read(self, value, sizeof(*value));
}

static bool stream_error(struct wic_stream *self)
{
    return self->error;
}

static bool stream_put_str(struct wic_stream *self, const char *str)
{
    return stream_write(self, str, strlen(str));
}

static bool stream_put_u8_masked(struct wic_stream *self, uint8_t value, const uint8_t *mask, uint8_t *unmasked)
{
    *unmasked = value ^ mask[self->pos % 4];
    
    return stream_put_u8(self, *unmasked);
}

static char b64_encode_byte(uint8_t in)
{
     static const char map[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
        'w', 'x', 'y', 'z', '0', '1', '2', '3', 
        '4', '5', '6', '7', '8', '9', '+', '/'
    };
    
    return map[in & 0x3fU];
}

static size_t b64_encode(const void *in, size_t len, char *out, size_t max)
{
    uint8_t c;
    uint8_t acc = 0U;
    size_t i;
    size_t retval = 0;
    
    if((max >= b64_encoded_size(len)) && (b64_encoded_size(len) >= len)){

        for(i=0U; i < len; i++){

            c = ((const uint8_t *)in)[i];

            switch(i%3U){
            default:
            case 0U:
                out[retval] = b64_encode_byte(c >> 2);
                retval++;
                acc = (c << 4);
                break;
            case 1U:
                out[retval] = b64_encode_byte(acc | (c >> 4));
                retval++;
                acc = (c << 2);
                break;            
            case 2U:
                out[retval] = b64_encode_byte(acc | (c >> 6));
                out[retval+1U] = b64_encode_byte(c);
                retval += 2U;
            }        
        }

        if((len % 3U) > 0U){
            
            out[retval] = b64_encode_byte(acc);
            out[retval+1U] = '=';
            retval += 2U;

            if((len % 3U) == 1U){
            
                out[retval] = '=';
                retval++;
            }
        }
    }
        
    return retval;
}

static size_t b64_encoded_size(size_t size)
{
    return (4 * ((size / 3) + ((size % 3) ? 1 : 0)));    
}

static int on_header_field(http_parser *http, const char *at, size_t length)
{
    struct wic_inst *self = http->data;

    switch(self->header_state){
    default:
        return -1;
    case WIC_HEADER_STATE_IDLE:        
    case WIC_HEADER_STATE_FIELD:
        stream_write(&self->rx.s, at, length);        
        break;
    case WIC_HEADER_STATE_VALUE:
        stream_put_u8(&self->rx.s, 0U);
        stream_write(&self->rx.s, at, length);        
        break;
    }

    self->header_state = WIC_HEADER_STATE_FIELD;

    return 0;
}

static int on_header_value(http_parser *http, const char *at, size_t length)
{
    struct wic_inst *self = http->data;

    switch(self->header_state){
    default:
    case WIC_HEADER_STATE_IDLE:
        return -1;
    case WIC_HEADER_STATE_FIELD:
        stream_put_u8(&self->rx.s, 0U);
        stream_write(&self->rx.s, at, length);
        break;    
    case WIC_HEADER_STATE_VALUE:
        stream_write(&self->rx.s, at, length);
        break;
    }

    self->header_state = WIC_HEADER_STATE_VALUE;
     
    return 0;
}

static void server_hash(const char *nonce, size_t len, uint8_t *hash)
{
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    sha1_context ctx;

    sha1_init(&ctx);
    (void)sha1_starts_ret(&ctx);
    (void)sha1_update_ret(&ctx, (const uint8_t *)nonce, len);
    (void)sha1_update_ret(&ctx, (const uint8_t *)guid, sizeof(guid)-1U);    
    (void)sha1_finish_ret(&ctx, hash);    
}

static bool str_equal(const char *s1, const char *s2)
{
    bool retval = false;
    size_t pos = 0U;

    if((s1 != NULL) && (s2 != NULL)){

        retval = true;

        for(;;){

            if(tolower(s1[pos]) != tolower(s2[pos])){

                retval = false;
                break;
            }

            if(s1[pos] == 0){

                break;
            }

            pos++;
        }
    }

    return retval;
}

static int on_request_complete(http_parser *http)
{
    struct wic_inst *self = http->data;
    const char *header;
    
    switch(self->header_state){
    case WIC_HEADER_STATE_IDLE:
        break;
    case WIC_HEADER_STATE_FIELD:
        WIC_DEBUG("unexpected state")
        return -1;    
    case WIC_HEADER_STATE_VALUE:
        stream_put_u8(&self->rx.s, 0U);
        break;
    }

    //check OK

    self->state = WIC_STATE_READY;

    /* expecting to have recevieved Connection: Upgrade */
    if(http->upgrade != 1){

        WIC_DEBUG("connection has not been upgraded")
        return -1;
    }

    /* check the upgrade protocol is websocket */
    header = wic_get_header(self, "upgrade");

    if(header == NULL){

        WIC_DEBUG("expecting an upgrade field")
        return -1;
    }

    if(!str_equal(header, "websocket")){

        WIC_DEBUG("unexpected upgrade field value")
        return -1;
    }

    /* check the mandatory Sec-WebSocket-Accept */
    header = wic_get_header(self, "Sec-WebSocket-Key");

    if(header == NULL){

        WIC_DEBUG("expecting Sec-WebSocket-Key header")
        return -1;
    }

    server_hash(header, strlen(header), self->hash);

    self->state = WIC_STATE_READY;

    return 0;
}

static int on_response_complete(http_parser *http)
{
    struct wic_inst *self = http->data;
    const char *header;
    char b64_hash[29U];

    WIC_ASSERT((b64_encoded_size(sizeof(self->hash))+1U) == sizeof(b64_hash))
    
    switch(self->header_state){
    default:
        break;
    case WIC_HEADER_STATE_VALUE:
        stream_put_u8(&self->rx.s, 0U);
        break;
    }

    self->state = WIC_STATE_READY;

    if(http->status_code != 101){

        switch(http->status_code){
        case 300U:
        case 301U:
        case 302U:
        case 303U:
        case 304U:
        case 307U:
            self->redirect_url = wic_get_header(self, "location");
            break;            
        default:
            break;
        }

        WIC_DEBUG("unexpected status code")
        return -1;
    }

    /* expecting to have recevieved Connection: Upgrade */
    if(http->upgrade != 1){

        WIC_DEBUG("connection has not been upgraded")
        return -1;
    }

    /* check the upgrade protocol is websocket */
    header = wic_get_header(self, "upgrade");

    if(header == NULL){

        WIC_DEBUG("expecting an upgrade field")
        return -1;
    }

    if(!str_equal(header, "websocket")){

        WIC_DEBUG("unexpected upgrade field value")
        return -1;
    }

    /* check the mandatory Sec-WebSocket-Accept */
    header = wic_get_header(self, "Sec-WebSocket-Accept");

    if(header == NULL){

        WIC_DEBUG("expecting Sec-WebSocket-Accept field")
        return -1;
    }

    b64_encode(self->hash, sizeof(self->hash), b64_hash, sizeof(b64_hash));
    b64_hash[sizeof(b64_hash)-1U] = 0;
    
    if(strcmp(header, b64_hash) != 0){

        WIC_DEBUG("unexpected Sec-WebSocket-Accept field value")
        return -1;
    }

    return 0;
}

static bool on_message(struct wic_inst *inst, enum wic_encoding encoding, bool fin, const char *data, uint16_t size)
{
    (void)inst;
    (void)encoding;
    (void)fin;
    (void)data;
    (void)size;

    return true;
}

#define UTF8
#ifdef UTF8
/* utf8_parse is based on:
 *
 * Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * */
static uint16_t utf8_parse(uint16_t state, char in)
{
    static const uint8_t utf8d[] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
        8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
        0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
        0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
        0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
        1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
        1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
        1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
    };

    uint16_t type;
    
    type = utf8d[(uint8_t)in];

    return utf8d[256U + state*16U + type];
}

static uint16_t utf8_parse_string(uint16_t state, const char *in, uint16_t len)
{
    uint16_t i;
    uint16_t s = state;

    for(i=0U; i < len; i++){

        s = utf8_parse(s, in[i]);
    }
    
    return s;
}

static bool utf8_is_complete(uint16_t state)
{
    return state == 0U;
}

static bool utf8_is_invalid(uint16_t state)
{
    return state == 1U;
}
#endif

#define SHA1
#ifdef SHA1
/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
static void sha1_init( sha1_context *ctx )
{
    (void)memset( ctx, 0, sizeof( sha1_context ) );
}

static int sha1_starts_ret( sha1_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    return( 0 );
}

static int internal_sha1_process( sha1_context *ctx, const unsigned char data[64] )
{
    uint32_t temp, W[16], A, B, C, D, E;

#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

    GET_UINT32_BE( W[ 0], data,  0 );
    GET_UINT32_BE( W[ 1], data,  4 );
    GET_UINT32_BE( W[ 2], data,  8 );
    GET_UINT32_BE( W[ 3], data, 12 );
    GET_UINT32_BE( W[ 4], data, 16 );
    GET_UINT32_BE( W[ 5], data, 20 );
    GET_UINT32_BE( W[ 6], data, 24 );
    GET_UINT32_BE( W[ 7], data, 28 );
    GET_UINT32_BE( W[ 8], data, 32 );
    GET_UINT32_BE( W[ 9], data, 36 );
    GET_UINT32_BE( W[10], data, 40 );
    GET_UINT32_BE( W[11], data, 44 );
    GET_UINT32_BE( W[12], data, 48 );
    GET_UINT32_BE( W[13], data, 52 );
    GET_UINT32_BE( W[14], data, 56 );
    GET_UINT32_BE( W[15], data, 60 );

#define S(x,n) (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

#define R(t)                                                    \
    (                                                           \
        temp = W[( (t) -  3 ) & 0x0F] ^ W[( (t) - 8 ) & 0x0F] ^ \
               W[( (t) - 14 ) & 0x0F] ^ W[  (t)       & 0x0F],  \
        ( W[(t) & 0x0F] = S(temp,1) )                           \
    )

#define P(a,b,c,d,e,x)                                          \
    do                                                          \
    {                                                           \
        (e) += S((a),5) + F((b),(c),(d)) + K + (x);             \
        (b) = S((b),30);                                        \
    } while( 0 )

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define K 0x5A827999

    P( A, B, C, D, E, W[0]  );
    P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  );
    P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  );
    P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  );
    P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  );
    P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] );
    P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] );
    P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] );
    P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) );
    P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) );
    P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))
#define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) );
    P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) );
    P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) );
    P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) );
    P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) );
    P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) );
    P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) );
    P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) );
    P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) );
    P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) );
    P( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) );
    P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) );
    P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) );
    P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) );
    P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) );
    P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) );
    P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) );
    P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) );
    P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) );
    P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) );
    P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))
#define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) );
    P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) );
    P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) );
    P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) );
    P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) );
    P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) );
    P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) );
    P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) );
    P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) );
    P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) );
    P( B, C, D, E, A, R(79) );

#undef K
#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;

    return( 0 );
}

static int sha1_update_ret( sha1_context *ctx, const unsigned char *input, size_t ilen )
{
    int ret;
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return( 0 );

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );

        if( ( ret = internal_sha1_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        if( ( ret = internal_sha1_process( ctx, input ) ) != 0 )
            return( ret );

        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );

    return( 0 );
}

static int sha1_finish_ret( sha1_context *ctx, unsigned char output[20] )
{
    int ret;
    uint32_t used;
    uint32_t high, low;

    /*
     * Add padding: 0x80 then 0x00 until 8 bytes remain for the length
     */
    used = ctx->total[0] & 0x3F;

    ctx->buffer[used++] = 0x80;

    if( used <= 56 )
    {
        /* Enough room for padding + length in current block */
        memset( ctx->buffer + used, 0, 56 - used );
    }
    else
    {
        /* We'll need an extra block */
        memset( ctx->buffer + used, 0, 64 - used );

        if( ( ret = internal_sha1_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        memset( ctx->buffer, 0, 56 );
    }

    /*
     * Add message length
     */
    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_BE( high, ctx->buffer, 56 );
    PUT_UINT32_BE( low,  ctx->buffer, 60 );

    if( ( ret = internal_sha1_process( ctx, ctx->buffer ) ) != 0 )
        return( ret );

    /*
     * Output final state
     */
    PUT_UINT32_BE( ctx->state[0], output,  0 );
    PUT_UINT32_BE( ctx->state[1], output,  4 );
    PUT_UINT32_BE( ctx->state[2], output,  8 );
    PUT_UINT32_BE( ctx->state[3], output, 12 );
    PUT_UINT32_BE( ctx->state[4], output, 16 );

    return( 0 );
}

#endif

