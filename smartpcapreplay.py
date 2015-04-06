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

def usage():
        print "##################################################################################################"
        print "               Smart PCAP Replay Utility with TCP Sessions"
        print "               Acts as if Client-Server is commuted"
        print "##################################################################################################"
        print "Usage : python smartpcapreplay.py -p tcp_mix.pcap -i 00:1d:xx:xx:xx:xx -o 10:1d:xx:xx:xx:xx"
        print "         -c 10.10.10.2 -s 20.20.20.2"
        print "-h --> help / Usage guidelines"
        print "-p --> PCAP to replay"
        print "-i --> DUT incoming Interface MAC Address"
        print "-o --> DUT outgoing Interface MAC Address"
        print "-c --> Client IP"
        print "-s --> Server IP/Destination IP"
        
        print " Target --> SNORT / HoneyPot / Firewall / WAF / Suricata / IPTables / IoT Gateway
        
        print " ~~~~~~~~~~~~~~~~~~TestBed~~~~~~~~~~~~~~~~~~~~~~~~~"
        print "                 |-------------|                   "
        print "         --------|   Target    |---------|         "
        print "         |   Eth1|-------------|Eth2     |         "
        print "         |                               |         "
        print "         |                               |         "
        print "         |       |----------|            |         "
        print "         |-------|   Linux  |------------|         "
        print "             Eth0|----------|Eth1                  "
        print " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        print "##################################################################################################"
        print "##################################################################################################"
        sys.exit(0)


