#!/usr/bin/python
__author__ = "Srinivas Naik (0xN41K)"
__license__ = "GPL"
__version__ = "1.0.1"
'''
Smart PCAP Replay is extension to TCPReplay tool which can smartly simulate Client and Server communications from 
given .pcap using single Host

naik@sec$ sudo pyhon smartpcapreplay.py mypacket_2gb.pcap -c eth0 -s eth1 -cmac 00:22:xx:xx:xx:xx \
          -smac 01:12:yy:yy:yy:yy
          
'''


