enum DiscreteMIMETypesIANA {
    MIME_APPLICATION,
    MIME_AUDIO,
    MIME_EXAMPLE,
    MIME_FONT,
    MIME_IMAGE,
    MIME_MODEL,
    MIME_TEXT,
    MIME_VIDEO
};


#define MIME_PARAM_MAX_LEN 16
struct MIME {
    char param[MIME_PARAM_MAX_LEN];
    char value[MIME_PARAM_MAX_LEN];
    unsigned is_multipart : 1;
    unsigned multipart_type : 1;
    unsigned type : 3;
    unsigned subtype : 4;
};

#define MAX_HTTP_HEADERS 16
struct HttpHeader {
    uint16_t begin_ptr, end_ptr;
};

struct HttpResponse {
    int status;
    char status_msg[100];
    int content_length;
    int content_type;

    int num_http_headers;
    struct HttpHeader headers[MAX_HTTP_HEADERS];

    uintptr_t content_ptr;
};

int parse_http_response(struct HttpResponse* resp, const char *buffer, int size) {
    const char *line_start = buffer,
               *line_end   = line_start;

    while (strncmp(line_end, CRLF))
        line_end++;

    

    return 0;
}