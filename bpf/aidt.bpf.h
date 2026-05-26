#ifndef __EVENTS_H__
#define __EVENTS_H__

#include "vmlinux.h"

#define UNUSED __attribute__((unused))

#define OK             0
#define AIDET_SNI_LEN  64

typedef enum aidt_event_type {
    EVENT_TYPE_PROCESS = 0,
    EVENT_TYPE_PROCESS_EXIT,
    EVENT_TYPE_CONNECT,
    EVENT_TYPE_SNI,
    EVENT_TYPE_MCP_CALL,
} aidt_event_type_e;

typedef enum aidt_conn_direction {
    CONN_DIR_OUTGOING = 0,
    CONN_DIR_INCOMING = 1,
} aidt_conn_direction_e;


typedef struct aidt_event {
    aidt_event_type_e type;
    u32               len;    // Length of the payload in msg[] 
    s8                msg[];  // Flexible array member: acts as a pointer to the payload 
} aidt_event_t;

typedef struct aidt_process_event {
    u32 pid;
    u32 ppid;
    u32 tgid;
    u64 cookie;     // Process start time used as a unique identifier
    s8  comm[16];
} aidt_process_event_t;

typedef struct aidt_conn_event {
    u32 pid;
    u64 cookie;     // Process start time of the connector
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    u8  direction;  // 0 for outgoing, 1 for incoming
} aidt_conn_event_t;


typedef struct aidt_sni_event {
    u32 pid;
    u64 cookie;     // Process start time of the connector
    char sni[AIDET_SNI_LEN];
} aidt_sni_event_t;

typedef struct aidt_mcp_call_event {
    u32 pid;
    u32 tgid;
    u64 cookie;
} aidt_mcp_call_event_t;

#endif /* __EVENTS_H__ */
