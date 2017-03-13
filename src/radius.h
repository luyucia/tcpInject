#ifndef _DPC_RADIUS_H
#define _DPC_RADIUS_H
extern "C" {
  #include <sys/types.h>
  }

#define PACKET_MAX_LEN  1500
#define PACKET_MIN_LEN  42
#define RADIUS_MIN_LEN 20
#define USER_NAME_SIZE 128

#define RADIUS_ACCOUNTING_REQUEST       4
#define RADIUS_AUTHENTICATOR_MAX_LEN    16

#define RADIUS_FINSHED_STATUS           3

#define RADIUS_ATTR_MAX_COUNT           (91)
#define RADIUS_ATTR_NAME                (1)
#define RADIUS_ATTR_IP                  (8)
#define RADIUS_ATTR_ACCT_STATUS_TYPE    (40)


#define RADIUS_ACCT_STATUS_START    1
#define RADIUS_ACCT_STATUS_STOP     2
#define RADIUS_ACCT_STATUS_UPDATE   3   //for cisco

typedef struct radius_head_s
{
    uint8_t  code;
    uint8_t  identifier;
    uint16_t length;
    char     authenticator[RADIUS_AUTHENTICATOR_MAX_LEN];
} radius_head_t;

//single radius attribute header struct
typedef struct radius_attr_s
{
    uint8_t type;
    uint8_t len;
} radius_attr_t;

#define USER_ONLINE     1
#define USER_OFFLINE    2
#define USER_UPDATE     3

#define IP_MAX_LEN      (32)
#define NAME_MAX_LEN    (28)

// int dpc_radius_attr(char *p_radius_attr, uint32_t radius_attr_len,
//         user_info_t *user_info);

#endif