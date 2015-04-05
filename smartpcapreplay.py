#!/usr/bin/python
__Author__ = "Srinivas Naik"

'''
Smart PCAP Replay is extension to TCPReplay tool which can smartly simulate Client and Server communications from 
given .pcap using single Host

naik@sec$ sudo pyhon smartpcapreplay.py mypacket_2gb.pcap -c eth0 -s eth1 -cmac 00:22:xx:xx:xx:xx \
          -smac 01:12:yy:yy:yy:yy
          
'''


