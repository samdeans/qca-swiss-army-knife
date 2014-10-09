#
# Copyright (c) 2012 Qualcomm Atheros, Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# trace-cmd plugin for ath10k, QCA Linux wireless driver


import tracecmd
import struct
import binascii


# enum htt_t2h_msg_type
HTT_T2H_MSG_TYPE_VERSION_CONF     = 0x0
HTT_T2H_MSG_TYPE_RX_IND           = 0x1
HTT_T2H_MSG_TYPE_RX_FLUSH         = 0x2
HTT_T2H_MSG_TYPE_PEER_MAP         = 0x3
HTT_T2H_MSG_TYPE_PEER_UNMAP       = 0x4
HTT_T2H_MSG_TYPE_RX_ADDBA         = 0x5
HTT_T2H_MSG_TYPE_RX_DELBA         = 0x6
HTT_T2H_MSG_TYPE_TX_COMPL_IND     = 0x7
HTT_T2H_MSG_TYPE_PKTLOG           = 0x8
HTT_T2H_MSG_TYPE_STATS_CONF       = 0x9
HTT_T2H_MSG_TYPE_RX_FRAG_IND      = 0xa
HTT_T2H_MSG_TYPE_SEC_IND          = 0xb
HTT_T2H_MSG_TYPE_TX_INSPECT_IND   = 0xd
HTT_T2H_MSG_TYPE_MGMT_TX_COMPL_IND= 0xe
HTT_T2H_MSG_TYPE_TX_CREDIT_UPDATE_IND   = 0xf
HTT_T2H_MSG_TYPE_RX_PN_IND              = 0x10
HTT_T2H_MSG_TYPE_RX_OFFLOAD_DELIVER_IND = 0x11
HTT_T2H_MSG_TYPE_TEST = 0x12

# enum htt_dbg_stats_status
HTT_DBG_STATS_STATUS_PRESENT = 0
HTT_DBG_STATS_STATUS_PARTIAL = 1
HTT_DBG_STATS_STATUS_ERROR   = 2
HTT_DBG_STATS_STATUS_INVALID = 3
HTT_DBG_STATS_STATUS_SERIES_DONE = 7

# enum htt_dbg_stats_type
HTT_DBG_STATS_WAL_PDEV_TXRX      = 0
HTT_DBG_STATS_RX_REORDER         = 1
HTT_DBG_STATS_RX_RATE_INFO       = 2
HTT_DBG_STATS_TX_PPDU_LOG        = 3
HTT_DBG_STATS_TX_RATE_INFO       = 4

def hexdump(buf, prefix=None):
    s = binascii.b2a_hex(buf)
    s_len = len(s)
    result = ""

    if prefix == None:
        prefix = ""

    for i in range(s_len / 2):
        if i % 16 == 0:
            result = result + ("%s%04x: " % (prefix, i))

        result = result + (s[2*i] + s[2*i+1] + " ")

        if (i + 1) % 16 == 0:
            result = result + "\n"

    # FIXME: if len(s) % 16 == 0 there's an extra \n in the end

    return result

wmi_scan_event_names = [
    [0x1,  "WMI_SCAN_EVENT_STARTED" ],
    [0x2,  "WMI_SCAN_EVENT_COMPLETED" ],
    [0x4, "WMI_SCAN_EVENT_BSS_CHANNEL" ],
    [0x8,  "WMI_SCAN_EVENT_FOREIGN_CHANNEL"],
    [0x10, "WMI_SCAN_EVENT_DEQUEUED" ],
    [0x20, "WMI_SCAN_EVENT_PREEMPTED" ],
    [0x40, "WMI_SCAN_EVENT_START_FAILED" ],
    ]

def wmi_event_scan(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<IIIIII", buf[0:24])
    event = hdr[0]
    reason = hdr[1]
    channel_freq = hdr[2]
    requestor = hdr[3]
    scan_id = hdr[4]
    vdev_id = hdr[5]

    trace_seq.puts("\t\t\t\tWMI_SCAN_EVENTID event 0x%x reason %d channel_freq %d requestor %d scan_id %d vdev_id %d\n" %
                   (event, reason, channel_freq, requestor, scan_id, vdev_id))

    for (i, name) in wmi_scan_event_names:
        if event == i:
            trace_seq.puts("\t\t\t\t\t%s" % name)

wmi_event_handlers = [
    [0x9000, wmi_event_scan ],
    ]

def wmi_cmd_start_scan_handler(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<IIIIIIIIIIIIIII", buf[0:60])
    scan_id = hdr[0]

    trace_seq.puts("\t\t\t\tWMI_START_SCAN_CMDID scan_id %d\n" % (scan_id))

wmi_cmd_handlers = [
    [0x9000, wmi_cmd_start_scan_handler ],
    ]

def ath10k_wmi_cmd_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    # parse wmi header
    hdr = struct.unpack("<HH", buf[0:4])
    buf = buf[4:]

    cmd_id = hdr[0]

    trace_seq.puts("id 0x%x len %d\n" % (cmd_id, buf_len))

    for (wmi_id, handler) in wmi_cmd_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf)
            break

def ath10k_wmi_event_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<HH", buf[0:4])
    cmd_id = hdr[0]

    trace_seq.puts("id 0x%x len %d\n" % (cmd_id, buf_len))

    for (wmi_id, handler) in wmi_event_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf[4:])
            break

def ath10k_log_dbg_dump_handler(pevent, trace_seq, event):
    msg = event['msg']
    prefix = event['prefix']
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    trace_seq.puts("%s\n" % (msg))
    trace_seq.puts("%s\n" % hexdump(buf, prefix))

def parse_htt_stats_tx_ppdu_log(pevent, trace_seq, buf, tlv_length):
    msg_hdr_len = 8
    msg_base_len = 40

    # struct ol_fw_tx_dbg_ppdu_msg_hdr
    l = msg_hdr_len
    hdr = struct.unpack("<BBBBI", buf[0:l])
    buf = buf[l:]

    mpdu_bytes_array_len = hdr[0]
    msdu_bytes_array_len = hdr[1]
    mpdu_msdus_array_len = hdr[2]
    reserved = hdr[3]
    microsec_per_tick = hdr[4]

    # 16 bit, 16 bit, 8 bit
    record_size = msg_base_len \
        + 2 * mpdu_bytes_array_len \
        + 2 * msdu_bytes_array_len \
        + 1 * mpdu_msdus_array_len
    records = (tlv_length - msg_hdr_len) / record_size

    trace_seq.puts("\t\t\trecords %d mpdu_bytes_array_len %d msdu_bytes_array_len %d mpdu_msdus_array_len %d reserved %d microsec_per_tick %d\n" % (records, mpdu_bytes_array_len, msdu_bytes_array_len, mpdu_msdus_array_len, reserved, microsec_per_tick))


    for i in range(records):
        # struct ol_fw_tx_dbg_ppdu_base
        l = msg_base_len
        hdr = struct.unpack("<HHIBBHIIIIIIBBBB", buf[0:l])
        buf = buf[l:]

        start_seq_num = hdr[0]
        start_pn_lsbs = hdr[1]
        num_bytes = hdr[2]
        num_msdus = hdr[3]
        num_mpdus = hdr[4]
        tid = hdr[5] & 0x1f
        peer_id = (hdr[5] & 0xffe) >> 5
        timestamp_enqueue = hdr[6]
        timestamp_completion = hdr[7]
        block_ack_bitmap_lsbs = hdr[8]
        block_ack_bitmap_msbs = hdr[9]
        enqueued_bitmap_lsbs = hdr[10]
        enqueued_bitmap_msbs = hdr[11]
        rate_code = hdr[12]
        rate_flags = hdr[13]
        tries = hdr[14]
        complete = hdr[15]

        trace_seq.puts("\t\t\t %d: start_seq_num %d start_pn_lsbs %d num_bytes %d num_msdus %d num_mpdus %d tid %d peer_id %d timestamp_enqueue %d timestamp_completion %d back %08x%08x enqueued %08x%08x rate_code 0x%x rate_flags 0x%x tries %d complete %d\n" % (i, start_seq_num, start_pn_lsbs, num_bytes, num_msdus, num_mpdus, tid, peer_id, timestamp_enqueue, timestamp_completion, block_ack_bitmap_msbs, block_ack_bitmap_lsbs, enqueued_bitmap_msbs, enqueued_bitmap_lsbs, rate_code, rate_flags, tries, complete))

def parse_htt_stats_conf_msg(pevent, trace_seq, buf):
    # parse HTT_T2H_STATS_CONF_TLV
    l = 12
    hdr = struct.unpack("<III", buf[0:l])
    buf = buf[l:]

    # 64 bit cookie
    cookie = hdr[0] | (hdr[1] << 32)

    tlv = hdr[2]

    # enum htt_dbg_stats_type: HTT_DBG_STATS_*
    tlv_type = (tlv >> 0) & 0x1f

    # enum htt_dbg_stats_status: HTT_DBG_STATS_STATUS_*
    tlv_status = (tlv & 0xe0) >> 5

    tlv_length = (tlv & 0xffff0000) >> 16

    trace_seq.puts("\t\tcookie 0x%016x tlv_type %d tlv_status %d tlv_length %d\n"
                   % (cookie, tlv_type, tlv_status, tlv_length))

    if tlv_type == HTT_DBG_STATS_TX_PPDU_LOG:
        parse_htt_stats_tx_ppdu_log(pevent, trace_seq, buf, tlv_length)

def ath10k_htt_stats_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    l = 4
    hdr = struct.unpack("<I", buf[0:l])
    buf = buf[l:]

    # enum htt_t2h_msg_type: HTT_T2H_MSG_TYPE_*
    htt_type = hdr[0]

    trace_seq.puts("len %d type %d\n" % (buf_len, htt_type))

    if htt_type == HTT_T2H_MSG_TYPE_STATS_CONF:
        parse_htt_stats_conf_msg(pevent, trace_seq, buf)
    
def register(pevent):
    pevent.register_event_handler("ath10k", "ath10k_wmi_cmd",
                                  lambda *args:
                                      ath10k_wmi_cmd_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_wmi_event",
                                  lambda *args:
                                      ath10k_wmi_event_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_log_dbg_dump",
                                  lambda *args:
                                      ath10k_log_dbg_dump_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_htt_stats",
                                  lambda *args:
                                      ath10k_htt_stats_handler(pevent, *args))
