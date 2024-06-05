#include "coap3/coap_internal.h"
#include "coap3/coap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int have_response = 0;

#ifndef COAP_CLIENT_URI
#define COAP_CLIENT_URI "coap://coap.me/hello"
#endif

#define COAP_LISTEN_UCAST_IP "::"


char test_buff[100] = {0};
int response_len = 0;


int
resolve_address(coap_str_const_t *host, uint16_t port, coap_address_t *dst,
                int scheme_hint_bits) {
  int ret = 0;
  coap_addr_info_t *addr_info;

  addr_info = coap_resolve_address_info(host, port, port,  port, port,
                                        0, scheme_hint_bits,
                                        COAP_RESOLVE_TYPE_REMOTE);
  if (addr_info) {
    ret = 1;
    *dst = addr_info->addr;
  }

  coap_free_address_info(addr_info);
  return ret;
}


static void coap_response_handler(coap_session_t *session,
                      const coap_pdu_t *sent,
                      const coap_pdu_t *received,
                      const coap_mid_t mid)
{
    size_t len;
    const uint8_t *databuf;
    size_t offset;
    size_t total;
    printf("have_response\n");
    have_response = 1;
    coap_show_pdu(COAP_LOG_WARN, received);
    if (coap_get_data_large(received, &len, &databuf, &offset, &total))
    {
        memcpy(test_buff+offset, databuf,len);
        if (len + offset == total)
        {
            test_buff[total] = 0;
            printf("recv[%d]:%.*s \r\n", total, total, test_buff);
            response_len = total;
        }
        
    }
    return COAP_RESPONSE_OK;
}


int ql_coap_send_recv(char *url, coap_pdu_code_t methods, char *data, int datalen, char *response, int buflen, int timeout_ms)
{

    coap_session_t *session = NULL;
    coap_optlist_t *optlist = NULL;
    coap_address_t dst;
    coap_pdu_t *pdu = NULL;
    coap_context_t *ctx = NULL;

    int result = -1;
    int len;
    int res;
    unsigned int wait_ms;
    coap_uri_t uri;
    const char *coap_uri = url;
    int is_mcast = 0;
    #define BUFSIZE 100
    unsigned char scratch[BUFSIZE];

    coap_startup();

    /* Parse the URI */
    len = coap_split_uri((const unsigned char *)coap_uri, strlen(coap_uri), &uri);
    if (len != 0)
    {
        printf("Failed to parse uri %s\n", coap_uri);
        goto finish;
    }

    /* resolve destination address where server should be sent */
    len = resolve_address(&uri.host, uri.port, &dst, 1 << uri.scheme);
    if (len <= 0)
    {
        printf("Failed to resolve address %*.*s\n", (int)uri.host.length,
                      (int)uri.host.length, (const char *)uri.host.s);
        goto finish;
    }
    is_mcast = coap_is_mcast(&dst);

    printf("is_mcast %d\n", is_mcast);

    /* create CoAP context and a client session */
    if (!(ctx = coap_new_context(NULL)))
    {
        printf("cannot create libcoap context\n");
        goto finish;
    }

    /* Support large responses */
    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

    if (uri.scheme == COAP_URI_SCHEME_COAP)
    {
        session = coap_new_client_session(ctx, NULL, &dst, COAP_PROTO_UDP);
    }

    if (!session)
    {
        printf("cannot create client session\n");
        goto finish;
    }

    /* coap_register_response_handler(ctx, response_handler); */
    coap_register_response_handler(ctx, coap_response_handler);
    /* construct CoAP message */
    pdu = coap_pdu_init(is_mcast ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
                        methods,
                        coap_new_message_id(session),
                        coap_session_max_pdu_size(session));
    if (!pdu)
    {
        printf("cannot create PDU\n");
        goto finish;
    }

    uint8_t token[8];
    size_t tokenlen;

    coap_session_new_token(session, &tokenlen, token);
    if (!coap_add_token(pdu, tokenlen, token))
    {
        coap_log_debug("cannot add token to request\n");
    }

    /* Add option list (which will be sorted) to the PDU */
    len = coap_uri_into_options(&uri, &dst, &optlist, 1, scratch, sizeof(scratch));
    if (len)
    {
        printf("Failed to create options\n");
        goto finish;
    }

    if (optlist)
    {
        coap_optlist_t *node = NULL;
        uint8_t buf[4];
        node = coap_new_optlist(COAP_OPTION_CONTENT_TYPE, coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_APPLICATION_JSON), buf);
        if (node)
        {
            coap_insert_optlist(&optlist, node);
        }

        res = coap_add_optlist_pdu(pdu, &optlist);
        if (res != 1)
        {
            printf("Failed to add options to PDU\n");
            goto finish;
        }
    }

    if (datalen > 0)
    {
        res = coap_add_data_large_request(session, pdu, datalen, data, NULL, NULL);
        if (!res)
        {
            goto finish;
        }
    }

    coap_show_pdu(COAP_LOG_WARN, pdu);

    /* and send the PDU */
    if (coap_send(session, pdu) == COAP_INVALID_MID)
    {
        coap_log_err("cannot send CoAP pdu\n");
        goto finish;
    }

    wait_ms = timeout_ms;

    while (have_response == 0 || is_mcast)
    {
        res = coap_io_process(ctx, 100);
        if (res >= 0)
        {
            if (wait_ms > 0)
            {
                if ((unsigned)res >= wait_ms)
                {
                    coap_log_err("timeout\n");
                    break;
                }
                else
                {
                    wait_ms -= res;
                }
            }
        }
    }

finish:

    if (have_response && response_len > 0)
    {
        if(response_len > sizeof(test_buff))
        {
            response_len = sizeof(test_buff);
        }
        memcpy(response, test_buff, response_len);
        result = 0;
    }
    else
    {
        result = -1;
    }
    have_response = 0;
    response_len = 0;

    coap_delete_optlist(optlist);
    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();
    return result;
}

int main(void)
{
#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    char send_data[] = "{\"test\":123}";
    char response[100] = {0};

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

#endif

    

    memset(response, 0, sizeof(response));

    if (ql_coap_send_recv(COAP_CLIENT_URI, COAP_REQUEST_CODE_GET, send_data, strlen(send_data), 
        response, sizeof(response), 3000) == 0)
    {
        printf("recv rsp:%s\r\n", response);
    }
    else
    {
        printf("ql_coap_send_recv timeout\r\n");
    }
#ifdef _WIN32
  WSACleanup();
#endif
    return 0;
}
