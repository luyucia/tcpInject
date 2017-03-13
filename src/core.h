

#ifndef _LYDPC_CORE_H_INCLUDED_
#define _LYDPC_CORE_H_INCLUDED_

#define  LYDPC_OK          0
#define  LYDPC_ERROR      -1
#define  LYDPC_AGAIN      -2
#define  LYDPC_BUSY       -3
#define  LYDPC_DONE       -4
#define  LYDPC_DECLINED   -5
#define  LYDPC_ABORT      -6

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_set>
#include <time.h>
#include <signal.h>
#include <exception>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>

#include <queue>
#include <iostream>
#include <string>
#include <regex.h>

#include "log.h"
#include "redis.h"
#include "config_loader.h"
#include "filter_policy.h"


#define NGX_HTTP_UNKNOWN   0x0001
#define NGX_HTTP_GET       0x0002
#define NGX_HTTP_HEAD      0x0004
#define NGX_HTTP_POST      0x0008
#define NGX_HTTP_PUT       0x0010
#define NGX_HTTP_DELETE    0x0020
#define NGX_HTTP_MKCOL     0x0040
#define NGX_HTTP_COPY      0x0080
#define NGX_HTTP_MOVE      0x0100
#define NGX_HTTP_OPTIONS   0x0200
#define NGX_HTTP_PROPFIND  0x0400
#define NGX_HTTP_PROPPATCH 0x0800
#define NGX_HTTP_LOCK      0x1000
#define NGX_HTTP_UNLOCK    0x2000
#define NGX_HTTP_PATCH     0x4000
#define NGX_HTTP_TRACE     0x8000

#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"

// struct http_header
// {
//     unsigned method;
//     char  referer[512];
//     char  url[512];
//     char  filename[128];
//     char  host[256];
//     char  userAgent[1024];
// };


struct http_header {
    char method[5];
    char path[2048];
    char fileName[512];
    char ext[50];
    char params[2048];
    char httpVersion[64];
    char referer[2048];
    char host[2048];
    char user_agent[2048];
    bool path_with_http = false;
    map<string, string> extraHeader;
};

struct push_decide{
    int type;
    char url[2048];
};


#define    COLOR_NONE                    "\033[0m"
#define    FONT_COLOR_RED             "\033[0;31m"
#define    FONT_COLOR_YELLOW             "\033[0;33m"
#define    FONT_COLOR_BLUE            "\033[1;34m"
#define    BACKGROUND_COLOR_RED        "\033[41m"
#define    BG_RED_FONT_YELLOW        "\033[41;33m"


#define PUSH_INTERVAL 2
#define HTTP_REQUEST_MAX_LEN 2048

#endif/*_LYDPC_CORE_H_INCLUDED_*/
