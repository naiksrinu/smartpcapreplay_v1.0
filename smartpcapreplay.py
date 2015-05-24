#!/usr/bin/python
__author__ = "Srinivas Naik (0xN41K)"
__license__ = "GPL"
__version__ = "1.0.1"
'''
Smart PCAP Replay is extension to TCPReplay tool which can smartly simulate Client and Server communications from 
given .pcap using single Host

naik@sec$ sudo python smartpcapreplay.py tcppacket_2gb.pcap -i 00:22:xx:xx:xx:xx \
          -o 01:12:yy:yy:yy:yy -c 10.10.10.2 -s 20.20.20.2
          
Target IP's: 
          Eth0: 10.10.10.1/24
          Eth1: 20.20.20.1/24
          
Linux IP's:
          Eth0: 10.10.10.2/24
          Eth1: 20.20.20.2/24
'''

def usage():
          print "##################################################################################################"
	print "		      		>>>	Smart PCAP Replay Utility	<<<		"
	print "		Description: i) The tool uses one single linux machine to simulate client & Server	"
	print "		      	     ii) Replays the PCAP with TCP Sessions 			"
	print "		      	     iii) Intresting tool to test web malwares / application detectors / Etc..	"
	print "	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	print "	PCAP Size limit: 40GB max.  |    Interfaces: 2 No. (Client/Server)  |  PyPackages: DPKT,SCAPY "
	print "##################################################################################################"
	print "Usage : python smartpcapreplay.py -p tcp-mix.pcap -i 00:1d:xx:xx:xx:xx -o 10:1d:xx:xx:xx:xx"
	print "		-c 10.10.10.2 -s 20.20.20.2"
	print "-h --> help / Usage guidelines"
	print "-p --> PCAP to replay"
	print "-i --> Target/Router/Honeypot incoming Interface MAC Address"
	print "-o --> Target/Router/HoneyPot outgoing Interface MAC Address"
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
          print " ***Note:	1. Manually enter client MAC (im) and Server MAC (om)				"
          print "##################################################################################################"
          sys.exit(0)


def tcp_flags(flags):
        ret = ''
        if flags & dpkt.tcp.TH_FIN:
                ret = ret + 'F'
        if flags & dpkt.tcp.TH_SYN:
                ret = ret + 'S'
        if flags & dpkt.tcp.TH_RST:
                ret = ret + 'R'
        if flags & dpkt.tcp.TH_PUSH:
                ret = ret + 'P'
        if flags & dpkt.tcp.TH_ACK:
                ret = ret + 'A'
        if flags & dpkt.tcp.TH_URG:
                ret = ret + 'U'
        if flags & dpkt.tcp.TH_ECE:
                ret = ret + 'E'
        if flags & dpkt.tcp.TH_CWR:
                ret = ret + 'C'
        return ret



def main():
	if len(sys.argv) <= 3:
		usage()
	im = "00:1d:a1:7C:78:00" #Local Machine Client MAC << Enter in Manually as per your setup
	om = "00:0d:88:00:47:A5" #Local Machine Server MAC << Enter in Manually as per your setup
	try:
		opts, args = getopt.getopt(sys.argv[1:], "h:p:i:o:c:s:")

	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit(-1)

	p = pcap = sip = smac = dmac = dip = ""


	for o, a in opts:
		if o in ("-h"):
			usage()
			sys.exit(0)
		elif o in ("-p", "-pcap"):
			f= file(a,"rb")
			pkts = dpkt.pcap.Reader(f)
			pcap = 1
		elif o in ("-i" , "-TiMac"): #Target Input Mac Address (E0/Eth0 interface)
			smac = a
		elif o in ("-o", "-ToMac"):  #Target Output Mac Address (E1/Eth1 interface)
			dmac = a
		elif o in ("-c", "-clientIP"): #Current Test Setup Client IP Address (E0/Eth0: 10.10.10.2)
			sip = a
		elif o in ("-s", "-serverIP"): #Current Test Setup Server IP Address (E1/Eth1: 20.20.20.2)
			dip = a
		else:
			print "See usage below: \n"
			usage()
			sys.exit(-1)

	if not pcap:
		print " Please give the Packet Capture file to Replay ..."
		usage()
		sys.exit(-1)
	
	#from scapy.all import *
	#pkts = dpkt.pcap.Reader(open('/root/fa.pcap'))
	#ip2f.session_list(pkts)
          iplist = open("sessions.log","r") #sessions.log file is created by ip2f.py
	
	for ips in iplist:
	   	print "\n\nReplaying Packets for Session %s" % (ips)
                time.sleep(2)	  
		for ts, pkt in pkts:
		    #print binascii.hexlify(str(pkt))
		    eth = dpkt.ethernet.Ethernet(pkt)
	            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                        continue
		    ip = eth.data
		    if ip.__class__ == dpkt.ip.IP:
		       srcip = socket.inet_ntoa(ip.src)
		       dstip = socket.inet_ntoa(ip.dst)
		       if (ip.p == 6) and (ip.data):
		       #if ip.p == 6:
		          protocol = ip.p
		          tcp = ip.data
		          #print repr(ip.tcp.data)
		          #print "IP:  %s %s %s %s" % (srcip, dstip, ip.tos,ip.p)
		          #print "TCP: %s %s %s %s" % (tcp.seq, off_x2, tcp_flags(tcp.flags), tcp.dport)
		          ipdata=repr(ip.data)
		          payload = tcp.data
			  text = ips.rstrip()
		          sip1 = re.findall(r'^(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',text)
		          dip1 = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3}$)',text)
		     
			  #time.sleep(0.1)	  
 			  if (srcip == sip1[0]) and (dstip == dip1[0]):
			          a=Ether(src =im, dst = smac)/IP(src=sip, dst=dip, proto= ip.p, flags=ip.data.flags)/TCP(seq= int(tcp.seq), sport= tcp.sport, dport = tcp.dport, ack= int(tcp.ack), flags=str(tcp_flags(tcp.flags)))/str(payload)
			  	  #delete  a[IP].chksum
				  print a.summary()
				  #print a.payload.payload

			  if (srcip == dip1[0]) and (dstip == sip1[0]):
			          a=Ether(src = om, dst = dmac)/IP(src=dip, dst=sip, proto= ip.p, flags=ip.data.flags)/TCP(seq = int(tcp.seq), sport= tcp.sport, dport = tcp.dport,ack= int(tcp.ack), flags=str(tcp_flags(tcp.flags)))/str(payload)
				  print a.summary()
		          #a=Ether()/IP(src=srcip, dst=dstip, tos=ip.tos,    proto= ip.p, flags=ip.data.flags)/TCP(seq=tcp.seq, sport= tcp.sport, dport = tcp.dport, flags=str(tcp_flags(tcp.flags)),dataofs= tcp.off_x2 )/repr(payload)
		          #delete IP.chksum
		          #exit(-1)


if __name__ == "__main__":
	main()

