#include "mbed.h"

namespace WIC {

    inline const char *nsapi_error_to_s(int32_t error)
    {
        const char *retval;

        switch(error){
        case NSAPI_ERROR_OK:
            retval = "OK";
            break;
        case NSAPI_ERROR_WOULD_BLOCK:
            retval = "WOULD_BLOCK";
            break;
        case NSAPI_ERROR_UNSUPPORTED:
            retval = "UNSUPPORTED";
            break;
        case NSAPI_ERROR_PARAMETER:
            retval = "PARAMETER";
            break;
        case NSAPI_ERROR_NO_CONNECTION:
            retval = "NO_CONNECTION";
            break;
        case NSAPI_ERROR_NO_SOCKET:
            retval = "NO_SOCKET";
            break;
        case NSAPI_ERROR_NO_ADDRESS:
            retval = "NO_ADDRESS";
            break;
        case NSAPI_ERROR_NO_MEMORY:
            retval = "NO_MEMORY";
            break;
        case NSAPI_ERROR_NO_SSID:
            retval = "NO_SSID";
            break;
        case NSAPI_ERROR_DNS_FAILURE:
            retval = "DNS_FAILURE";
            break;
        case NSAPI_ERROR_DHCP_FAILURE:
            retval = "DHCP_FAILURE";
            break;
        case NSAPI_ERROR_AUTH_FAILURE:
            retval = "AUTH_FAILURE";
            break;
        case NSAPI_ERROR_DEVICE_ERROR:
            retval = "DEVICE_ERROR";
            break;
        case NSAPI_ERROR_IN_PROGRESS:
            retval = "IN_PROGRESS";
            break;
        case NSAPI_ERROR_ALREADY:
            retval = "ALREADY";
            break;
        case NSAPI_ERROR_IS_CONNECTED:
            retval = "IS_CONNECTED";
            break;
        case NSAPI_ERROR_CONNECTION_LOST:
            retval = "CONNECTION_LOST";
            break;
        case NSAPI_ERROR_CONNECTION_TIMEOUT:
            retval = "CONNECTION_TIMEOUT";
            break;
        case NSAPI_ERROR_ADDRESS_IN_USE:
            retval = "ADDRESS_IN_USE";
            break;
        case NSAPI_ERROR_TIMEOUT:
            retval = "TIMEOUT";
            break;
        case NSAPI_ERROR_BUSY:
            retval = "BUSY";
            break;
        default:
            retval = "UNKNOWN";
            break;
        }

        return retval;        
    }
};
