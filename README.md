smartpcapreplay
===============

Replay the PCAPS with Sessions from same host.


smartpcapreplay.py  --- Main file to replay the given PCAP in Sessions as per your setup 

ip2f.py             --- Supportive function to identify the sessions and filter the IP's from the pcap, this file                            creates an log file having list of Session based IP's.

help                --- This document gives the glance to prepare your setup



Detail Test Bed:

  	        |----------|		     
		--------|  Target  |-------|       
		|     E0|----------|E1	   |        
	  |                 			   |        
		|			                     |         
	  |	      |----------|	     |         
	  |-------|  Linux   |-------|         
	        E0|----------|E1		     


Target IP's: 
          Eth0: 10.10.10.1/24
          Eth1: 20.20.20.1/24
          
Linux IP's:
          Eth0: 10.10.10.2/24
          Eth1: 20.20.20.2/24

naik@sec$ sudo python smartpcapreplay.py tcppacket_2gb.pcap -i 00:22:xx:xx:xx:xx \
          -o 01:12:yy:yy:yy:yy -c 10.10.10.2 -s 20.20.20.2
         


