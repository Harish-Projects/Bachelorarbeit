#!/usr/bin/env python3

import pyshark
import pandas as pd
import pickle
import sklearn
from custom_classes import SampleSubsetSelector
import logging
import sys

##-----------------------------------------------------------------------------##

# Function to catch the command line arguments error
def throw_err(argument):
    """
    This function takes an argument from the command line and performs some action.

    Args:
        argument: The argument passed from the command line.
    """
    print(f"Received number of arguments exceeds the desired: {argument}")

##-----------------------------------------------------------------------------##

# Datatype to manage the features
class FeaturesManager:
    def __init__(self):
        self.default_features = {
            # arp infos
            'arp.opcode': 0,
            'arp.hw.size': 0,
            # icmp infos
            'icmp.checksum': 0,
            'icmp.seq_le': 0,
            # http infos
            'http.content_length' : 0,
            'http.request.method': 0,
            'http.referer': 0,
            'http.request.version': 0,
            'http.response': 0,
            # tcp infos
            'tcp.ack': 0,
            'tcp.ack_raw': 0,
            'tcp.checksum': 0,
            'tcp.connection.fin': 0,
            'tcp.connection.rst': 0,
            'tcp.connection.syn': 0,
            'tcp.connection.synack': 0,
            'tcp.flags':  0, # needed?
            'tcp.flags.ack':  0, 
            'tcp.len': 0,  
            'tcp.seq': 0,
            # udp infos
            'udp.stream': 0,
            'udp.time_delta': 0,
            # dns infos
            'dns.qry.name': 0,
            'dns.qry.name.len': 0,
            'dns.qry.qu': 0,
            'dns.qry.type': 0,
            'dns.retransmission': 0,
            'dns.retransmit_request': 0,
            'dns.retransmit_request_in': 0,
            #mqtt infos
            'mqtt.conack.flags': 0,
            'mqtt.conflag.cleansess': 0,
            'mqtt.conflags': 0,
            'mqtt.hdrflags': 0,
            'mqtt.len': 0,
            'mqtt.msgtype': 0,
            'mqtt.proto_len': 0,
            'mqtt.topic_len': 0,
            'mqtt.ver': 0,
            #mbtcp infos
            'mbtcp.len': 0,
        } 
        self.features = self.default_features.copy()
        self.IP_dest = None # destination IP
        self.IP_src = None # source IP 

    def update(self, dict_args):
        self.features.update(dict_args)
        return self.features

    def reset(self):
        self.features = self.default_features.copy()

##-----------------------------------------------------------------------------##

# Global Objects
manager = FeaturesManager() 
interface_arg = None
model_arg = None
logging.basicConfig(
    filename='../data/Prediction.log',  # File to write logs to
    level=logging.INFO,      # Logging level
    format='%(levelname)s - %(message)s'  # Log format
)
columns = ['arp.opcode', 'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'http.content_length', 'http.request.method', 'http.referer', 'http.request.version', 'http.response',
                'tcp.ack', 'tcp.ack_raw', 'tcp.checksum', 'tcp.connection.fin', 'tcp.connection.rst', 'tcp.connection.syn', 'tcp.connection.synack', 'tcp.flags', 'tcp.flags.ack',
                'tcp.len', 'tcp.seq', 'udp.stream', 'udp.time_delta', 'dns.qry.name', 'dns.qry.name.len', 'dns.qry.qu', 'dns.qry.type', 'dns.retransmission', 'dns.retransmit_request',
                'dns.retransmit_request_in', 'mqtt.conack.flags', 'mqtt.conflag.cleansess', 'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msgtype', 'mqtt.proto_len', 'mqtt.topic_len',
                'mqtt.ver', 'mbtcp.len']

categorical_columns = ['http.request.method', 'http.referer', 'http.request.version', 'dns.qry.name', 'mqtt.conack.flags']
numerical_columns = [col for col in columns if col not in categorical_columns]

##-----------------------------------------------------------------------------##

# Function to load the model
def load_model(model_type):
    with open(f'/data/{model_type}_model.pkl', "rb") as model_file:
        model = pickle.load(model_file)
    return model

def predict(model_arg, samples):
    prediction = model_arg.predict(samples)
    return prediction

##-----------------------------------------------------------------------------##

# Callback Fuction to process each packet
def process_packet(pkt):
    if('arp' in pkt):
        manager.update({'arp.opcode': pkt.arp.opcode, 'arp.hw.size': pkt.arp.hw_size})
    if('tcp' in pkt):
        manager.update({'tcp.ack': pkt.tcp.ack, 'tcp.ack_raw': pkt.tcp.ack_raw, 'tcp.connection.fin': pkt.tcp.flags_fin,
                                    'tcp.connection.rst': pkt.tcp.flags_reset, 'tcp.connection.syn': pkt.tcp.flags_syn, 
                                    'tcp.connection.synack': 1 if((pkt.tcp.flags_ack ==1)&(pkt.tcp.flags_syn == 1)) else 0,
                                    'tcp.flags.ack': pkt.tcp.flags_ack, 'tcp.flags': pkt.tcp.flags, 'tcp.len': pkt.tcp.len,
                                    'tcp.checksum': pkt.tcp.checksum, 'tcp.seq': pkt.tcp.seq})
    if('udp' in pkt):
        if(pkt.udp.has_field('time_delta')):
            manager.update({'udp.time_delta' :pkt.udp.time_delta})
        manager.update({'udp.stream': pkt.udp.stream})
    if('icmp' in pkt):
        if(pkt.icmp.has_field('seq_le')):
            manager.update({'icmp.seq_le': pkt.icmp.seq_le})
        manager.update({'icmp.checksum': pkt.icmp.checksum})
    if('http' in pkt):
        if(pkt.http.has_field('response')):
            manager.update({'http.response': 1})
        else:
            manager.update({'http.response': 0})
        if(pkt.http.has_field('request')):
            manager.update({'http.content_length': pkt.http.content_length, 'http.request.method': pkt.http.request_method,
                                    'http.request.version': pkt.http.request_version, 'http.referer': pkt.http.referer}) 
    if(('dns' in pkt) & ('dns.qry.name' in pkt)): # pkt.dns.qry_name
        manager.update({'dns.qry.name': pkt.dns.qry_name, 'dns.qry.name.len': pkt.dns.qry_name_len, 'dns.qry.type': pkt.dns.qry_type})
    if('mdns' in pkt):
        if(pkt.mdns.has_field('dns_qry_name')):
            manager.update({'dns.qry.name': pkt.mdns.dns_qry_name, 'dns.qry.name.len': pkt.mdns.dns_qry_name_len,
                            'dns.qry.type': pkt.mdns.dns_qry_type, 'dns.qry.qu': pkt.mdns.dns_qry_qu})
        if(pkt.mdns.has_field('dns_retransmission')):
            manager.update({'dns.retransmission': pkt.mdns.dns_retransmission})
            if(pkt.mdns.has_field('dns_retransmission_request')):
                manager.update({'dns.retransmit_request': pkt.mdns.dns_retransmit_request, 'dns.retransmit_request_in': pkt.mdns.dns_retransmit_request_in})
    if('mqtt' in pkt):
        if(pkt.mqtt.has_field('topic_len')):
            manager.update({'mqtt.topic_len': pkt.mqtt.topic_len})
        if(pkt.mqtt.has_field('conflags')):
            manager.update({'mqtt.conflag.cleansess': pkt.mqtt.conflag_cleansess, 'mqtt.conflags': pkt.mqtt.conflags})
        if(pkt.mqtt.has_field('proto_len')):
            manager.update({'mqtt.proto_len': pkt.mqtt.proto_len})
        if(pkt.mqtt.has_field('ver')):
            manager.update({'mqtt.ver': pkt.mqtt.ver})
        manager.update({'mqtt.hdrflags': pkt.mqtt.hdrflags, 'mqtt.len': pkt.mqtt.len, 'mqtt.msgtype': pkt.mqtt.msgtype})
    if('mbtcp' in pkt):
        manager.update({'mbtcp.len': pkt.mbtcp.len}).values()

    # Extract the IP addresses
    if('ip' in pkt):
        manager.IP_src = pkt.ip.src
        manager.IP_dest = pkt.ip.dst

    temp = pd.DataFrame(manager.features, index=[0])

    temp[categorical_columns] = temp[categorical_columns].astype('object')
    #temp[numerical_columns] = temp[numerical_columns].astype('float64')
    
    #print(temp.info())
    #print(temp.dtypes)

    return temp

#-------------------------------------------------------------------------------#

## Main Function
if __name__ == '__main__':

    # For the CLI arguments management
    if len(sys.argv) > 3:
        argument = sys.argv[1]
        throw_err(argument)
    else:
        interface_arg = sys.argv[2]
        model_arg = sys.argv[1]
    
    # Load the model
    model = load_model(model_arg)
    print("ML-Model loaded successfully!")

    # From Live Capture
    live_cap = pyshark.LiveCapture(interface= interface_arg) #, capture_filter = '')# output_file= 'live_capture.csv' ) 
    print("Live Capture Started!")

    for packet in live_cap.sniff_continuously(packet_count = 30): # Param: packet_count=None, timeout=None # Reading from a Live Capture
        test = process_packet(packet)
        logging.info(f"DataFrame Columns: {test.columns.tolist()}")
        logging.info(f"DataFrame values:\n{test.values}")
        pred = model.predict(test)
        print(f"Prediction: {pred}")
        logging.info(f"Prediction: {pred} : from IP: {manager.IP_src} to IP: {manager.IP_dest}")
        manager.reset()

    ############      (OR)     ####################
    #live_cap.apply_on_packets(process_packet); # Param: callback, timeout=None. packet_count=None

    ## From Capture file
    # cap = pyshark.FileCapture(args.file_path, keep_packets=False) 
    # cap.apply_on_packets(process_packet)#, packet_count=100)

    print("Program Ended extracted successfully!")

