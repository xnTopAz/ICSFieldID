import binascii
import argparse
import json
import sys

import bacnet_tracer
import mms_tracer
import s7_tracer

from tracer import SymTracer
import pdml_parser
import ast_parser

import ipdb

def analysis(protocol):
	if protocol == "bacnet":
		protocol_tracer = bacnet_tracer
	elif protocol == "mms":
		protocol_tracer = mms_tracer
	elif protocol == "s7":
		protocol_tracer = s7_tracer
	else:
		raise("unknow protocl")
	binary = protocol_tracer.binary
	start_addr = protocol_tracer.start_addr
	end_addr = protocol_tracer.end_addr
	recv_hook = protocol_tracer.recv_hook
	hooks = protocol_tracer.hooks
	memory_store = protocol_tracer.memory_store
	packet_path = protocol_tracer.packet_path
	key_funs = protocol_tracer.key_funs

	pdml_parser.g_protocol = protocol
	packets = pdml_parser.parse_pdml(packet_path)
	features = {}

	tags = ast_parser.init_feature_dict()
	tags_list = list(tags.keys())
	with open("tags.json", "w") as f:
		json.dump(tags_list, f)
	
	for idx, packet in packets.items():
		frame_no = packet[0]['frame_no']
		print(frame_no)
		for field in packet:
			print(field)

		features[frame_no] = {}
		tracer = SymTracer(protocol_name=protocol, binary=binary, lib=None, packet=packet, start_addr=start_addr, end_addr=end_addr, recv_hook=recv_hook, hooks=hooks, memory_store=memory_store, key_funs=key_funs)
		
		expr_collection = tracer.analysis()
		secs = tracer.secs
		instr_seq = tracer.instr_seq
		symbol_map = tracer.trace_symbol_map
		field_feature = ast_parser.parse_expr_collection(expr_collection, secs, instr_seq, symbol_map)

		for key, val in field_feature.items():
			features[frame_no][key] = val
		print("fields num:", len(field_feature))

	tmp_file = protocol + ".features.json"
	with open(tmp_file, 'w', encoding='utf-8') as f:
		json.dump(features, f, ensure_ascii=False)

def main():
	parser = argparse.ArgumentParser(description='ICSFieldID')
	parser.add_argument('-p', '--protocol', required=True, help='Protocol name')
	args = parser.parse_args()

	protocol = args.protocol
	analysis(protocol)

if __name__ == '__main__':
	main()