#!/usr/bin/env python3

import pyshark
import pandas as pd
import sys

# Function to catch the command line arguments error
def throw_err(argument):
    """
    This function takes an argument from the command line and performs some action.

    Args:
        argument: The argument passed from the command line.
    """
    print(f"Received number of arguments exceeds the desired: {argument}")

# Datatype to manage the features
class FeaturesManager:
    def __init__(self):
        self.default_features = {
            # arp infos
            'arp_opcode': 0,
            'arp_hwtype': 0,
            # tcp infos
            'tcp_ack': 0,
            'tcp_ack_raw': 0,
            'tcp_conn_fin': 0,
            'tcp_conn_rst': 0,
            'tcp_conn_syn': 0,
            'tcp_conn_sa': 0,
            'tcp_flags_ack': 0,
            'tcp_flags': 0, # needed? 
            'tcp_len': 0, 
            'tcp_checksum': 0,
            'tcp_seq': 0,
            # udp infos
            'udp_stream': 0,
            'udp_time_delta': 0,
            # icmp infos
            'icmp_checksum': 0,
            'icmp_seq_le': 0,
            # http infos
            'http_content_len' :0,
            'http_request_method': 0,
            'http_referer': 0,
            'http_request_version': 0,
            'http_response': 0,
            # dns infos
            'dns_qry_name': 0,
            'dns_qry_len': 0,
            'dns_qry_type': 0,
            'dns_qry_qu':0,
            'dns_retransmission': 0,
            'dns_retransmission_request': 0,
            'dns_retransmission_request_in': 0,
            #mqtt infos
            'mqtt_conflag_cleansess': 0,
            'mqtt_conflags': 0,
            'mqtt_hdrflags': 0,
            'mqtt_len': 0,
            'mqtt_msgtype': 0,
            'mqtt_proto_len': 0,
            'mqtt_topic_len': 0,
            'mqtt_ver': 0,
            #mbtcp infos
            'mbtcp_len': 0,

        } 
        self.features = self.default_features.copy()

    def update(self, dict_args):
        self.features.update(dict_args)
        return self.features

    def reset(self):
        self.features = self.default_features.copy()

# Global Objects
manager = FeaturesManager() 
val = [] # list of dictionaries !!!maximum size of list is 536870912 in 32 bit system, so packet_count should be limited to that.
interface_arg = None

# Callback Fuction to process each packet
def process_packet(pkt):
    if('arp' in pkt):
        val.append(manager.update({'arp_opcode': pkt.arp.opcode, 'arp_hwsize': pkt.arp.hw_size}).values())
    if('tcp' in pkt):
        val.append(manager.update({'tcp_ack': pkt.tcp.ack, 'tcp_ack_raw': pkt.tcp.ack_raw, 'tcp_conn_fin': pkt.tcp.flags_fin,
                                    'tcp_conn_rst': pkt.tcp.flags_reset, 'tcp_conn_syn': pkt.tcp.flags_syn, 
                                    'tcp_conn_sa': 1 if((pkt.tcp.flags_ack ==1)&(pkt.tcp.flags_syn == 1)) else 0,
                                    'tcp_flags_ack': pkt.tcp.flags_ack, 'tcp_flags': pkt.tcp.flags, 'tcp_len': pkt.tcp.len,
                                    'tcp_checksum': pkt.tcp.checksum, 'tcp_seq': pkt.tcp.seq}).values())
    if('udp' in pkt):
        if(pkt.udp.has_field('time_delta')):
            manager.update({'udp_time_delta' :pkt.udp.time_delta})
        val.append(manager.update({'udp_stream': pkt.udp.stream}).values())
    if('icmp' in pkt):
        if(pkt.icmp.has_field('seq_le')):
            manager.update({'icmp_seq_le': pkt.icmp.seq_le})
        val.append(manager.update({'icmp_checksum': pkt.icmp.checksum}).values())
    if('http' in pkt):
        if(pkt.http.has_field('response')):
            manager.update({'http_response': 1})
        else:
            manager.update({'http_response': 0})
        if(pkt.http.has_field('request')):
            val.append(manager.update({'http_content_len': pkt.http.content_length, 'http_request_method': pkt.http.request_method,
                                    'http_request_version': pkt.http.request_version, 'http_referer': pkt.http.referer}).values()) 
    if(('dns' in pkt) & ('dns.qry_name' in pkt)):
        val.append(manager.update({'dns_qry_name': pkt.dns.qry_name, 'dns_qry_len': pkt.dns.qry_name_len, 'dns_qry_type': pkt.dns.qry_type}).values())
    if('mdns' in pkt):
        if(pkt.mdns.has_field('dns_qry_name')):
            manager.update({'dns_qry_name': pkt.mdns.dns_qry_name, 'dns_qry_len': pkt.mdns.dns_qry_name_len,
                            'dns_qry_type': pkt.mdns.dns_qry_type, 'dns_qry_qu': pkt.mdns.dns_qry_qu})
        if(pkt.mdns.has_field('dns_retransmission')):
            manager.update({'dns_retransmission': pkt.mdns.dns_retransmission})
            if(pkt.mdns.has_field('dns_retransmission_request')):
                manager.update({'dns_retransmission_request': pkt.mdns.dns_retransmit_request, 'dns_retransmit_request_in': pkt.mdns.dns_retransmit_request_in})
        val.append(manager.features.values())
    if('mqtt' in pkt):
        if(pkt.mqtt.has_field('topic_len')):
            manager.update({'mqtt_topic_len': pkt.mqtt.topic_len})
        if(pkt.mqtt.has_field('conflags')):
            manager.update({'mqtt_conflag_cleansess': pkt.mqtt.conflag_cleansess, 'mqtt_conflags': pkt.mqtt.conflags})
        if(pkt.mqtt.has_field('proto_len')):
            manager.update({'mqtt_proto_len': pkt.mqtt.proto_len})
        if(pkt.mqtt.has_field('ver')):
            manager.update({'mqtt_ver': pkt.mqtt.ver})
        val.append(manager.update({'mqtt_hdrflags': pkt.mqtt.hdrflags, 'mqtt_len': pkt.mqtt.len, 'mqtt_msgtype': pkt.mqtt.msgtype}).values())
    if('mbtcp' in pkt):
        val.append(manager.update({'mbtcp_len': pkt.mbtcp.len}).values())

    manager.reset()

if __name__ == '__main__':

    # For the CLI arguments
    if len(sys.argv) > 2:
        argument = sys.argv[1]
        throw_err(argument)
    else:
        interface_arg = sys.argv[1]

    # From Live Capture
    live_cap = pyshark.LiveCapture(interface= interface_arg) #, capture_filter = '')# output_file= 'live_capture.csv' ) 
    print("Live Capture Started!")
    for packet in live_cap.sniff_continuously(packet_count=5): # Param: packet_count=None, timeout=None # Reading from a Live Capture
        process_packet(packet)
    # (OR)
    #live_cap.apply_on_packets(process_packet); # Param: callback, timeout=None. packet_count=None

    ## From Capture file
    # cap = pyshark.FileCapture(args.file_path, keep_packets=False) 
    # cap.apply_on_packets(process_packet)#, packet_count=100)


    # Dataframe of extracted features
    columns_list = ['arp_opcode','arp_hwsize',
                    'tcp_ack', 'tcp_ack_raw', 'tcp_conn_fin', 'tcp_conn_rst', 'tcp_conn_syn',
                    'tcp_conn_sa', 'tcp_flags_ack', 'tcp_flags', 'tcp_len', 'tcp_checksum', 'tcp_seq',
                    'udp_stream', 'udp_time_delta',
                    'icmp_checksum', 'icmp_seq_le',
                    'http_content_len', 'http_request_method', 'http_referer', 'http_request_version', 'http_response',
                    'dns_qry_name', 'dns_qry_len', 'dns_qry_type', 'dns_qry_qu', 'dns_retransmission', 'dns_retransmission_request', 'dns_retransmission_request_in',
                    'mqtt_conflag_cleansess','mqtt_conflags', 'mqtt_hdrflags', 'mqtt_len', 'mqtt_msgtype',
                    'mqtt_proto_len', 'mqtt_topic_len', 'mqtt_ver', 'mbtcp_len','arp_opcode2']
    df = pd.DataFrame(val, columns=columns_list)

    print(df.head(5))
    #print(df.info())
    #df.to_csv('features.csv', index=False)

    print("Features extracted successfully!")

