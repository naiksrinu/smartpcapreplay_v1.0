#!/usr/bin/python

'''
This part of code will read PCAP and Filter Sessions available in PCAP

'''
__author__ = "Srinivas Naik (0xN41K)"
__license__ = "GPL"
__version__ = "1.0.1"

import dpkt
import os, sys
from scapy.all import *
from dpkt.ip import IP
pcapfile= sys.argv[1]

def session_list(pcapf):
        pkts= dpkt.pcap.Reader(open(pcapf))
        #pkts= dpkt.pcap.Reader(open("facebook.cap"))

        for tstamp, pkt1 in pkts:
                eth= dpkt.ethernet.Ethernet(pkt1)
                ip = eth.data
                tcp= ip.data
         
                if ip.__class__ == dpkt.ip.IP:
                       srcip = socket.inet_ntoa(ip.src)
                       dstip = socket.inet_ntoa(ip.dst)
                       if ip.p == 6:
                        if tcp.flags == 2:
                                #print "Client IP: %s" % srcip
                                fl=str(tcp.flags)
                                fi = open('iplog','a')
                                fi.write(srcip +"--"+ dstip + "\n")
                                #print " %s : %s " % (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))
        fi.close()
        u = set(open('iplog').readlines())
        sess = open('sessions.log','w').writelines(set(u))
        #sess.close()
        iplist = open("sessions.log","r")
        for ips in iplist:
             ipselect = ips.rstrip()
             #sip = re.findall(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})',ipselect)
             sip = re.findall(r'^(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',ipselect)
             dip = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3}$)',ipselect)
             print "Client IP: %s <----> Server IP: %s" % (sip[0], dip[0])


session_list(pcapfile)
