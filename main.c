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

#include <stdio.h>

#include "chatbot_secrets.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

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
#if 0
    // We have a valid connection
    const char http_request_oauth_token[] = "POST " REQUEST_OAUTH2_TOKEN " HTTP/1.1\n" "Host: " TWITCH_HOSTNAME "\n" "Accept: application/json\n" "Accept-Encoding: \n" "Accept-Language: en-?US, en; q=0.5\n" "Content-Type: application/x-www-form-urlencoded\n\n";

#define BUFLEN 2048
    char recvbuf[BUFLEN];
    int recvbuflen = BUFLEN; 

    // Send request
    if ((ws_result = send(s->sock, http_request_oauth_token, (int) sizeof http_request_oauth_token, 0)) == SOCKET_ERROR) {
        printf("send failed: %d\n", WSAGetLastError());
        closesocket(s->sock);
        WSACleanup();
        return 1;
    }

    printf("Bytes sent: %ld\n", ws_result);

    // shutdown the connection for sending since no more data will be sent
    // the client can still use the ConnectSocket for receiving data
    ws_result = shutdown(s->sock, SD_SEND);
    if (ws_result == SOCKET_ERROR) {
        printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(s->sock);
        WSACleanup();
        return 1;
    }

    // Receive data until the server closes the connection
    do {
        ws_result = recv(s->sock, recvbuf, recvbuflen, 0);
        if (ws_result > 0)
            printf("Bytes received: %d\n", ws_result);
        else if (ws_result == 0)
            printf("Connection closed\n");
        else
            printf("recv failed: %d\n", WSAGetLastError());
    } while (ws_result > 0);

    printf("Recv: %s\n", recvbuf);
#endif
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

int main(int argc, char *argv[]) {
    const char *hostname = "id.twitch.tv";
    const char *path = "/oauth2/token" "?client_id=" CLIENT_ID "&client_secret=" CLIENT_SECRET "&grant_type=client_credentials"; 
    struct TLSSocket s;
    if (tls_connect(&s, "id.twitch.tv", "443") != 0) {
        printf("Error connecting to %s\n", hostname);
        return -1;
    }

    printf("Connected!\n");


    printf("Disconnected!\n");
    tls_disconnect(&s);
    return 0;
}