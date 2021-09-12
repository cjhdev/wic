History
=======

## 0.3.0

- updated LICENSE file to show license banner text for all components
- rename 'port' directory to 'wrapper'
- replace WIC_PORT_INCLUDE macro with requirement to always have a file called 'wic_config.h' in include path
- SHA1 code (Apache 2.0) is now clearly separated from MIT licensed code
- renamed standard close reasons from WIC_CLOSE_xxx to WIC_CLOSE_REASON_xxx
- close reasons are now enums instead of preprocessor macros to catch spelling mistakes
- added wic_convert_close_reason() to convert standard close reason enums to integer codes

## 0.2.2

- moved all mbed examples into examples/mbed
- added makefile for compiling all MBED examples
- added docker file for setting up MBED build environment
- removed the rogue .mbedignore stopping MBED tcp client example from compiling

## 0.2.1

- default port is now set when no port is included in the URL
- the MBED wrapper is now passing all non-perf tests

## 0.2.0

Many enhancements to the original concept, the most significant being improved
handshaking and ability to signal blocking on send/receive. I've changed most
of the original interfaces.

- added `wic_on_buffer_fn` callback for allocating a transmit buffer
  and indicating when socket is not able to buffer
- added buffer type field to `wic_on_buffer_fn` and `wic_on_send_fn`
  to support buffer prioritisation (i.e. so a pong doesn't disappear)
- added `wic_on_handshake_failure_fn` callback to indicate a failed handshake
- added `wic_on_close_transport_fn` callback as a dedicated handler for
  closing the transport
- added `wic_on_ping_fn` callback
- added `wic_on_pong_fn` callback
- removed `wic_send_pong*` interfaces
- changed URL schema to be an enum rather than string
- added mbed port work in progress
- fixed the echo example (was previously closing prematurely)

## 0.1.0

First release.
