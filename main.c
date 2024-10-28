#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <winerror.h>

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <Security.h>
#include <schannel.h>
#include <shlwapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")

#include <stdio.h>
#include <assert.h>

#include "chatbot_secrets.h"

#define JSMN_STATIC
#include "jsmn.h"

// payload + extra over head for header/mac/padding (probably an overestimate)
#define TLS_MAX_PACKET_SIZE (16384 + 512)
typedef unsigned char byte;
typedef unsigned short u16;

struct TLSSocket {
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;
    int used;
    int available;
    char* decrypted;
    char incoming[TLS_MAX_PACKET_SIZE];
};

static int tls_connect(struct TLSSocket *s, const char *hostname, const char *port)
{
    WSADATA wsa_data;

    int ws_result = WSAStartup(MAKEWORD(2,2), &wsa_data);
    if (ws_result != 0) {
        printf("WSAStartup failed: %d\n", ws_result);
        return 1;
    }

    struct addrinfo *addrs = NULL, *ptr = NULL, hints;

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    ws_result = getaddrinfo(hostname, port, &hints, &addrs);
    if (ws_result != 0) {
        printf("getaddrinfo failed: %d\n", ws_result);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to all retreived addresses
    for (ptr = addrs, s->sock = INVALID_SOCKET;
         ptr != NULL && s->sock == INVALID_SOCKET;
         ptr = ptr->ai_next)
    {
        // Create a SOCKET for connecting to server
        if ((s->sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) != INVALID_SOCKET) {
            // Connect to the server
            if ((ws_result = connect(s->sock, ptr->ai_addr, (int)ptr->ai_addrlen)) != SOCKET_ERROR) {
                break;
            }

            closesocket(s->sock);
            s->sock = INVALID_SOCKET;
        }

        printf("Error at socket(): %d\n", WSAGetLastError());
    }

    // Check if there was any successful connection
    if (s->sock == INVALID_SOCKET) {
        printf("Unable to conenct to server!\n");
        freeaddrinfo(addrs);
        WSACleanup();
        return 1;
    }

    // By this point, we have a valid connection and we can start with the TLS handshake
    // initialize schannel
    SCH_CREDENTIALS creds = {
        .dwVersion = SCH_CREDENTIALS_VERSION,
        .dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
                    | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
                    | SCH_CRED_NO_DEFAULT_CREDS     // no client certificate authentication
    };

    if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, (void*)&creds, NULL, NULL, &s->handle, NULL) != SEC_E_OK) {
        closesocket(s->sock);
        WSACleanup();
        return -1;
    }

    s->received = s->used = s->available = 0;
    s->decrypted = NULL;

    CtxtHandle* context = NULL;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = {0};
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming;
        inbuffers[0].cbBuffer = s->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = {0};
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS sec = InitializeSecurityContextA(
            &s->handle,
            context,
            context ? NULL : (SEC_CHAR*)hostname,
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &flags,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        context = &s->context;

        // check if there is extra data
        if (inbuffers[1].BufferType == SECBUFFER_EXTRA) {
            MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            s->received = inbuffers[1].cbBuffer;
        }
        else
        {
            s->received = 0;
        }

        if (sec == SEC_E_OK) {
            // tls handshake complete
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            char* buffer = outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d;
                if ((d = send(s->sock, buffer, size, 0)) <= 0)
                    break;

                size -= d;
                buffer += d;
            }

            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0) {
                // failed to fully send data to server
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            result = -1;
            break;
        }

        // read more data from server when possible
        if (s->received == sizeof(s->incoming))
        {
            // server is sending too much data instead of proper handshake?
            result = -1;
            break;
        }

        int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
        if (r == 0)
        {
            // server disconnected socket
            return 0;
        }
        else if (r < 0)
        {
            result = -1;
            break;
        }
        s->received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        WSACleanup();
        return result;
    }

    if (QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes) != SEC_E_OK) {
        return -1;
    }

    return 0;
}


static int tls_write(struct TLSSocket *s, const void *buffer, int size)
{
    while (size != 0) {
        int use = min(size, s->sizes.cbMaximumMessage);
        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK) {
            // this should not happen, but just in case check it
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer,
            sent = 0;

        while (sent != total) {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
                return -1; // error sending data through socket, or server disconnected
            
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }

    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
static int tls_read(struct TLSSocket *s, void *buffer, int size)
{
    int result = 0;

    while (size != 0) {
        if (s->decrypted) {
            // if there is decrypted data available, then use it as much as possible
            int use = min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use; // advance buffer ptr
            size -= use;
            result += use;

            if (use == s->available) {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = NULL;
            } else {
                s->available -= use;
                s->decrypted += use;
            }
        } else {
            // if any ciphertext data avilable then try to decrypt it
            if (s->received != 0) {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                // this is the raw encrypted input buffer
                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;

                buffers[1].BufferType = buffers[2].BufferType = buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);\
                if (sec == SEC_E_OK) {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = buffers[1].pvBuffer;
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                } else if (sec == SEC_I_CONTEXT_EXPIRED) {
                    // server closed TLS connection (but socket is still open)
                    s->received = 0;
                    return result;
                } else if (sec == SEC_I_RENEGOTIATE) {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                } else if (sec != SEC_E_INCOMPLETE_MESSAGE) {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }

            // otherwise not enough data received to decrypt
            if (result != 0) {
                break;
            }

            if (s->received == sizeof(s->incoming)) {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
            if (r <= 0) {
                // server disconnected socket
                return 0;
            } else if (r < 0) {
                return -1; // error receiving data from socket
            }

            s->received += r;
        }
    }

    return result;
}

static int tls_disconnect(struct TLSSocket* s)
{
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof type;

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    if (ApplyControlToken(&s->context, &indesc) != SEC_E_OK) {
        return -1;
    }

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_STREAM;

    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;

        int d;
        for (; size != 0; buffer += d, size -= d) {
            if (d = send(s->sock, buffer, size, 0), d <= 0)
                break; // ignore all failures, socket will be closed anyway
        }

        FreeContextBuffer(outbuffers[0].pvBuffer);
    }

    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
    WSACleanup();
    return 0;
}

#define TWITCH_ID_HOSTNAME "id.twitch.tv"
#define TWITCH_API_HOSTNAME "api.twitch.tv" 
#define OAUTH2_TOKEN_PATH "/oauth2/token" "?client_id=" CLIENT_ID "&client_secret=" CLIENT_SECRET "&grant_type=client_credentials" 
#define CRLF "\x0D\x0A"
#define CHAT_CHANNEL_USER_ID "saidwho13"
#define CHATBOT_USER_ID "saidwho13"


int make_https_request(struct TLSSocket* s, const char *req, int req_len, char *res, int max_resp_len) {
    int err;
    if (err = tls_write(s, req, req_len), err != 0) {
        printf("tls_write failed\n");
        return -1;
    }

    int res_len;
    if (res_len = tls_read(s, res, max_resp_len), res_len <= 0) {
        printf("tls_read failed\n");
        return -1;
    }

    return res_len;
}

int send_chat_message(struct TLSSocket* s, const char *oauth_token, const char* msg)
{
    char req[1024], res[1024];
    int req_len, res_len;
    req_len = snprintf(req, sizeof(req), "POST /helix/chat/messages HTTP/1.1" CRLF "Authorization: Bearer %s" CRLF "Client-Id: " CLIENT_ID CRLF "Content-Type: application/json" CRLF CRLF "{broadcaster_id: \"" CHAT_CHANNEL_USER_ID "\", sender_id: \"" CHATBOT_USER_ID "\", message: \"%s\"}" CRLF CRLF,
        oauth_token, msg);

    if (res_len = make_https_request(s, req, req_len, res, sizeof(res)), res_len <= 0) {
        printf("Failed to make HTTP request to server\n");
        return -1;
    }

    printf("HTTP REQUEST:\n%.*s\n", req_len, req);
    printf("HTTP RESPONSE:\n%.*s\n", res_len, res);

    return res_len;
}

int main(void) {
    struct TLSSocket twitch_id_socket, twitch_api_socket;
    if (tls_connect(&twitch_id_socket, TWITCH_ID_HOSTNAME, "443") != 0) {
        printf("Error connecting to %s\n", TWITCH_ID_HOSTNAME);
        return -1;
    }
    printf("Connected to %s\n", TWITCH_ID_HOSTNAME);

    if (tls_connect(&twitch_api_socket, TWITCH_API_HOSTNAME, "443") != 0) {
        printf("Error connecting to %s\n", TWITCH_API_HOSTNAME);
        return -1;
    }

    printf("Connected to %s\n", TWITCH_API_HOSTNAME);

    char req[1024], res[1024];
    int req_len, res_len;
    
    // Request oauth2 token from twitch
    req_len = snprintf(req, sizeof(req), "POST " "/oauth2/token" "?client_id=" CLIENT_ID "&client_secret=" CLIENT_SECRET "&grant_type=client_credentials" " HTTP/1.1" CRLF "Host: " TWITCH_ID_HOSTNAME CRLF "Content-Type: application/x-www-form-urlencoded" CRLF CRLF);
    if (res_len = make_https_request(&twitch_id_socket, req, req_len, res, sizeof(res)), res_len <= 0) {
        printf("Error getting Oauth2 token\n");
        return -1;
    }

    int times = 2;
    int i = 0, data_start, data_end;
    while (i <= res_len - 4 && times) {
        if (!memcmp(&res[i], CRLF CRLF, 4)) {
            if (times == 2) {
                data_start = i + 4;
            } else if (times == 1) {
                data_end = i;
            }

            --times;
        }

        ++i;
    }

    printf("data: %.*s\n", data_end - data_start, &res[data_start]);
    char oauth_token[32];
    ZeroMemory(oauth_token, sizeof(oauth_token));

    {
        jsmn_parser p;
        jsmntok_t t[128];
        jsmn_init(&p);
        int r = jsmn_parse(&p, &res[data_start], data_end - data_start, t, sizeof(t));
        CopyMemory(oauth_token, &res[data_start + t[2].start], t[2].end - t[2].start);
        // while (--r) {
        //     printf("Token: %.*s\n", t[r].end - t[r].start, &res[data_start + t[r].start]);
        // }
    }
    printf("OAuth2 Token: %s\n", oauth_token);

    // Validate OAuth2 token
    req_len = snprintf(req, sizeof(req), "GET /oauth2/validate HTTP/1.1" CRLF "Authorization: Bearer %s" CRLF CRLF, oauth_token);
    if (res_len = make_https_request(&twitch_id_socket, req, req_len, res, sizeof(res)), res_len <= 0) {
        printf("Error validating Oauth2 token\n");
        return -1;
    }

    printf("HTTP RESPONSE:\n%.*s\n", res_len, res);

    printf("Validated OAuth2 token\n");

    send_chat_message(&twitch_api_socket, oauth_token, "Hello, Chat!");

    tls_disconnect(&twitch_id_socket);
    tls_disconnect(&twitch_api_socket);
    printf("Disconnected!\n");
    return 0;
}