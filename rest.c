

/* Body of reply to OFPST_FLOW request. */
struct ofpFlowStats {
    uint16T length          /* Length of this entry. */
    uint8T tableId         /* ID of table flow came from. */
    uint8T pad
    struct ofpMatch match   /* Description of fields. */
    uint32T durationSec    /* Time flow has been alive in seconds. */
    uint32T durationNsec   /* Time flow has been alive in nanoseconds beyond
                                 durationSec. */
    uint16T priority        /* Priority of the entry. Only meaningful
                                 when this is not an exact-match entry. */
    uint16T idleTimeout    /* Number of seconds idle before expiration. */
    uint16T hardTimeout    /* Number of seconds before expiration. */
    uint8T pad2[6]          /* Align to 64-bits. */
    uint64T cookie          /* Opaque controller-issued identifier. */
    uint64T packetCount    /* Number of packets in flow. */
    uint64T byteCount      /* Number of bytes in flow. */
    struct ofpActionHeader actions[0] /* Actions. */
}
OFP_ASSERT(sizeof(struct ofpFlowStats) == 88)

/* Body for ofpStatsRequest of type OFPST_AGGREGATE. */
struct ofpAggregateStatsRequest {
    struct ofpMatch match   /* Fields to match. */
    uint8T tableId         /* ID of table to read (from ofpTableStats)
                                 0xff for all tables or 0xfe for emergency. */
    uint8T pad              /* Align to 32 bits. */
    uint16T outPort        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_NONE
                                 indicates no restriction. */
}
OFP_ASSERT(sizeof(struct ofpAggregateStatsRequest) == 44)

/* Body of reply to OFPST_AGGREGATE request. */
struct ofpAggregateStatsReply {
    uint64T packetCount    /* Number of packets in flows. */
    uint64T byteCount      /* Number of bytes in flows. */
    uint32T flowCount      /* Number of flows. */
    uint8T pad[4]           /* Align to 64 bits. */
}
OFP_ASSERT(sizeof(struct ofpAggregateStatsReply) == 24)

/* Body of reply to OFPST_TABLE request. */
struct ofpTableStats {
    uint8T tableId        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8T pad[3]          /* Align to 32-bits. */
    char name[OFP_MAX_TABLE_NAME_LEN]
    uint32T wildcards      /* Bitmap of OFPFW_* wildcards that are
                                supported by the table. */
    uint32T maxEntries    /* Max number of entries supported. */
    uint32T activeCount   /* Number of active entries. */
    uint64T lookupCount   /* Number of packets looked up in table. */
    uint64T matchedCount  /* Number of packets that hit table. */
}
OFP_ASSERT(sizeof(struct ofpTableStats) == 64)

/* Body for ofpStatsRequest of type OFPST_PORT. */
struct ofpPortStatsRequest {
    uint16T portNo        /* OFPST_PORT message must request statistics
                              * either for a single port (specified in
                              * portNo) or for all ports (if portNo ==
                              * OFPP_NONE). */
    uint8T pad[6]
}
OFP_ASSERT(sizeof(struct ofpPortStatsRequest) == 8)

/* Body of reply to OFPST_PORT request. If a counter is unsupported set
 * the field to all ones. */
struct ofpPortStats {
    uint16T portNo
    uint8T pad[6]          /* Align to 64-bits. */
    uint64T rxPackets     /* Number of received packets. */
    uint64T txPackets     /* Number of transmitted packets. */
    uint64T rxBytes       /* Number of received bytes. */
    uint64T txBytes       /* Number of transmitted bytes. */
    uint64T rxDropped     /* Number of packets dropped by RX. */
    uint64T txDropped     /* Number of packets dropped by TX. */
    uint64T rxErrors      /* Number of receive errors.  This is a super-set
                                of more specific receive errors and should be
                                greater than or equal to the sum of all
                                rx_*Err values. */
    uint64T txErrors      /* Number of transmit errors.  This is a super-set
                                of more specific transmit errors and should be
                                greater than or equal to the sum of all
                                tx_*Err values (none currently defined.) */
    uint64T rxFrameErr   /* Number of frame alignment errors. */
    uint64T rxOverErr    /* Number of packets with RX overrun. */
    uint64T rxCrcErr     /* Number of CRC errors. */
    uint64T collisions     /* Number of collisions. */
}
OFP_ASSERT(sizeof(struct ofpPortStats) == 104)

/* Vendor extension. */
struct ofpVendorHeader {
    struct ofpHeader header   /* Type OFPT_VENDOR. */
    uint32T vendor            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
    /* Vendor-defined arbitrary additional data. */
}
OFP_ASSERT(sizeof(struct ofpVendorHeader) == 12)

/* All ones is used to indicate all queues in a port (for stats retrieval). */
#define OFPQ_ALL      0xffffffff

/* Min rate > 1000 means not configured. */
#define OFPQ_MIN_RATE_UNCFG      0xffff

enum ofpQueueProperties {
    OFPQT_NONE = 0       /* No property defined for queue (default). */
    OFPQT_MIN_RATE       /* Minimum datarate guaranteed. */
                          /* Other types should be added here
                           * (i.e. max rate precedence etc). */
}

/* Common description for a queue. */
struct ofpQueuePropHeader {
    uint16T property    /* One of OFPQT_. */
    uint16T len         /* Length of property including this header. */
    uint8T pad[4]       /* 64-bit alignemnt. */
}
OFP_ASSERT(sizeof(struct ofpQueuePropHeader) == 8)

/* Min-Rate queue property description. */
struct ofpQueuePropMinRate {
    struct ofpQueuePropHeader propHeader /* prop: OFPQT_MIN len: 16. */
    uint16T rate        /* In 1/10 of a percent >1000 -> disabled. */
    uint8T pad[6]       /* 64-bit alignment */
}
OFP_ASSERT(sizeof(struct ofpQueuePropMinRate) == 16)

/* Full description for a queue. */
struct ofpPacketQueue {
    uint32T queueId     /* id for the specific queue. */
    uint16T len          /* Length in bytes of this queue desc. */
    uint8T pad[2]        /* 64-bit alignment. */
    struct ofpQueuePropHeader properties[0] /* List of properties. */
}
OFP_ASSERT(sizeof(struct ofpPacketQueue) == 8)

/* Query for port queue configuration. */
struct ofpQueueGetConfigRequest {
    struct ofpHeader header
    uint16T port         /* Port to be queried. Should refer
                              to a valid physical port (i.e. < OFPP_MAX) */
    uint8T pad[2]        /* 32-bit alignment. */
}
OFP_ASSERT(sizeof(struct ofpQueueGetConfigRequest) == 12)

/* Queue configuration for a given port. */
struct ofpQueueGetConfigReply {
    struct ofpHeader header
    uint16T port
    uint8T pad[6]
    struct ofpPacketQueue queues[0] /* List of configured queues. */
}
OFP_ASSERT(sizeof(struct ofpQueueGetConfigReply) == 16)

struct ofpQueueStatsRequest {
    uint16T portNo        /* All ports if OFPT_ALL. */
    uint8T pad[2]          /* Align to 32-bits. */
    uint32T queueId       /* All queues if OFPQ_ALL. */
}
OFP_ASSERT(sizeof(struct ofpQueueStatsRequest) == 8)

struct ofpQueueStats {
    uint16T portNo
    uint8T pad[2]          /* Align to 32-bits. */
    uint32T queueId       /* Queue i.d */
    uint64T txBytes       /* Number of transmitted bytes. */
    uint64T txPackets     /* Number of transmitted packets. */
    uint64T txErrors      /* Number of packets dropped due to overrun. */
}
OFP_ASSERT(sizeof(struct ofpQueueStats) == 32)



