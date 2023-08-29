#!/usr/bin/env python3
import os
import sys

from scapy.all import (
	TCP,
	IP,
	FieldLenField,
	FieldListField,
	IntField,
	IPOption,
	ShortField,
	get_if_list,
	Packet,
	Ether,
	BitField,
	bind_layers,
	PacketListField,
	sniff
)
from scapy.layers.inet import _IPOption_HDR

def get_if():
	ifs=get_if_list()
	iface=None
	for i in get_if_list():
		if "eth0" in i:
			iface=i
			break;
	if not iface:
		print("Cannot find eth0 interface")
		exit(1)
	return iface

"""
class IPOption_MRI(IPOption):
	name = "MRI"
	option = 31
	fields_desc = [ _IPOption_HDR,
					FieldLenField("length", None, fmt="B",
								  length_of="swids",
								  adjust=lambda pkt,l:l+4),
					ShortField("count", 0),
					FieldListField("swids",
								   [],
								   IntField("", 0),
								   length_from=lambda pkt:pkt.count*4) ]
"""

class INT_filho(Packet):
	fields_desc = [ BitField("swid", 0, 32),
					BitField("porta_entrada", 0, 9),
					BitField("porta_saida", 0, 9),
					BitField("timestamp", 0, 48),
					BitField("qdepth", 0, 32),
					BitField("padding", 0, 6)]
	def extract_padding(self, p):
		return "", p

class INT(Packet):
	name = "INT"
	fields_desc = [ BitField("quantidade_filhos", 0, 32),
					BitField("next_protocol", 0, 16),
					PacketListField("filhos",
					 				[],
									INT_filho,
									count_from=lambda pkt:(pkt.quantidade_filhos*1))]

def handle_pkt(pkt):
	if TCP in pkt and pkt[TCP].dport == 1234:
		print("got a packet")
		pkt.show2()
	#    hexdump(pkt)
		sys.stdout.flush()

def main():
	ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
	iface = ifaces[0]
	print("sniffing on %s" % iface)
	sys.stdout.flush()
	bind_layers(Ether, INT, type=0x88B5)
	bind_layers(INT, IP, next_protocol=0x800)
	sniff(iface = iface,
		  prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
	main()
