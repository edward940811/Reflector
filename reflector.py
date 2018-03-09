#! /usr/bin/env python
import socket
import sys
import argparse
import getopt
import traceback
from scapy.all import *

def secondphasepackage(pkt):
	attacker_ip = pkt[IP].src
	attacker_ethernet = pkt[Ether].src
	pkt[Ether].dst = attacker_ethernet
	pkt[IP].dst = attacker_ip
	return pkt

def reflectorcallback(pkt):
	try:
		if ARP in pkt:
			if pkt[ARP].pdst == victim_ip:
				arpreply = Ether(src = victim_ethernet, dst = pkt[Ether].src)/ARP(psrc = victim_ip,hwsrc = victim_ethernet ,pdst = pkt[ARP].psrc , hwdst = pkt[ARP].hwsrc, op = 2)
				#print arpreply.show()
				sendp(arpreply, iface = interface)

			elif pkt[ARP].pdst == reflector_ip: #second phase
				print pkt.show()
				arpreply = Ether(src = reflector_ethernet, dst = pkt[Ether].src) /ARP(hwsrc = reflector_ethernet, psrc = reflector_ip, hwdst=pkt[ARP].hwsrc, pdst = pkt[ARP].psrc, op = 2)
				sendp(arpreply, iface = interface)

		else:
			if pkt[IP].dst == victim_ip:
				pkt = secondphasepackage(pkt)
				pkt[Ether].src = reflector_ethernet
				pkt[IP].src = reflector_ip
				del pkt.chksum
				if pkt.haslayer(TCP):
					del pkt[TCP].chksum
				elif pkt.haslayer(UDP):
					del pkt[UDP].chksum
				elif pkt.haslayer(ICMP):
					del pkt[ICMP].chksum
				sendp(pkt, iface = interface)
				pkt.show2()



			elif pkt[IP].dst == reflector_ip:
				pkt = secondphasepackage(pkt)
				pkt[Ether].src = victim_ethernet
				pkt[IP].src = victim_ip
				del pkt.chksum
				if pkt.haslayer(TCP):
					del pkt[TCP].chksum
				elif pkt.haslayer(UDP):
					del pkt[UDP].chksum
				elif pkt.haslayer(ICMP):
					del pkt[ICMP].chksum
				pkt.show2()
				sendp(pkt, iface = interface)
				pkt.show2()
	except Exception as e:
		print(traceback.format_exc())
		print e

parser = argparse.ArgumentParser(description='Testing input arg...')
parser.add_argument('--victim-ip',type=str, help='foo help')  #-- means optional - means _
parser.add_argument('--victim-ethernet',type=str, help='foo help')
parser.add_argument('--interface',type=str, help='foo help')
parser.add_argument('--reflector-ethernet',type=str, help='foo help')
parser.add_argument('--reflector-ip',type=str, help='foo help')

args = parser.parse_args()

interface = args.interface
victim_ip = args.victim_ip
victim_ethernet = args.victim_ethernet
reflector_ip = args.reflector_ip
reflector_ethernet = args.reflector_ethernet

sniff(iface = interface, prn = reflectorcallback)
