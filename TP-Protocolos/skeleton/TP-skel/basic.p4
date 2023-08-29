/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800; // | 2048  | Internet Protocol version 4 (IPv4) as defined in RFC 791.
const bit<16> TYPE_INT = 0x88B5; // | 34997 | Local Experimental EtherType 1 as defined in IEEE Std 802.

#define MAX_HOPS 3

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header pai_t {
	bit<32> quantidade_filhos;
	bit<16> next_protocol;
}

header filho_t {
	bit<32> swid;
	bit<9> porta_entrada;
	bit<9> porta_saida;
	bit<48> timestamp;
	bit<32> qdepth;
	bit<6> padding; // O tamanho do cabecalho em bits deve ser multiplo de 8 | de 130 para 136 = 17 bytes
}

header ipv4_t {
	bit<4>    version;
	bit<4>    ihl;
	bit<8>    diffserv;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>    flags;
	bit<13>   fragOffset;
	bit<8>    ttl;
	bit<8>    protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

struct parser_metadata_t {
	bit<32>  remaining;
}

struct metadata {
	parser_metadata_t parser_metadata;
	}

struct headers {
	ethernet_t	ethernet;
	pai_t		pai;
	filho_t[MAX_HOPS]	filho;
	ipv4_t		ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
				out headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4: parse_ipv4;
			TYPE_INT: parse_pai;
			default: accept;
		}
	}

	state parse_pai {
		packet.extract(hdr.pai);
		meta.parser_metadata.remaining = hdr.pai.quantidade_filhos;
		transition select(meta.parser_metadata.remaining) {
			0: parse_ipv4; //caso para testes, pai nunca vai ter 0 filhos nesse state
			default: parse_filho; //parse_filho;
		}
	}

 	state parse_filho {
		packet.extract(hdr.filho.next);
		meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
		transition select(meta.parser_metadata.remaining) {
			0: parse_ipv4;
			default: parse_filho;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition accept;
	}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {
	action drop() {
		mark_to_drop(standard_metadata);
	}

	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	table ipv4_lpm {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			ipv4_forward;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	apply {
		if (hdr.ipv4.isValid()) {
			ipv4_lpm.apply();
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata) {
	action add_pai(bit<32> swid) {
		hdr.pai.setValid();
		hdr.pai.quantidade_filhos = 1;
		hdr.pai.next_protocol = hdr.ethernet.etherType;

		hdr.ethernet.etherType = TYPE_INT;

 		hdr.filho.push_front(1);
		hdr.filho[0].setValid();
		hdr.filho[0].swid = swid; 
		hdr.filho[0].porta_entrada = standard_metadata.ingress_port;
		hdr.filho[0].porta_saida = standard_metadata.egress_spec;
		hdr.filho[0].timestamp = standard_metadata.egress_global_timestamp;
		hdr.filho[0].qdepth = standard_metadata.deq_timedelta;
	}

/* 	action add_filho() {
//lorem ipsum
	} */

	table pai_table {
		actions = {
			add_pai;
			NoAction;
		}
		default_action = NoAction();
	}
	
	apply {
		if (hdr.pai.isValid() == false) {
			pai_table.apply();
		}
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
	 apply {
		update_checksum(
		hdr.ipv4.isValid(),
			{ hdr.ipv4.version,
			  hdr.ipv4.ihl,
			  hdr.ipv4.diffserv,
			  hdr.ipv4.totalLen,
			  hdr.ipv4.identification,
			  hdr.ipv4.flags,
			  hdr.ipv4.fragOffset,
			  hdr.ipv4.ttl,
			  hdr.ipv4.protocol,
			  hdr.ipv4.srcAddr,
			  hdr.ipv4.dstAddr },
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16);
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.pai);
		packet.emit(hdr.filho);
		packet.emit(hdr.ipv4);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
