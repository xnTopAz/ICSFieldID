import claripy
from itertools import groupby
from collections import defaultdict

import ipdb

NOFLAG = 0
MEM_WRITE_DST = 0x1
MEM_WRITE_SRC = 0x2
MEM_WRITE_LEN = 0x4
MEM_READ_ADDR = 0x8
MEM_READ_VAL = 0x10
MEM_READ_LEN = 0x20
ADDR_DATA = 0x40
ADDR_STACK = 0x80

g_op_mapping = {
	'__and__': 'has_and',
	'And': 'has_and',
	'__sub__': 'has_sub',
	'__or__': 'has_or',
	'Or': 'has_or',
	'__mul__': 'has_mul',
	'__xor__': 'has_xor',
	'Not': 'has_not',
	'__lshift__': 'has_shl',
	'__rshift__': 'has_shr',
	'LShR': 'has_shr',
	'Extract': 'has_extract',
	# 'Concat': 'has_concat',
	'Reverse': 'has_reverse',
	'ZeroExt': 'has_ext',	
	'__ne__': 'has_ne',
	'__eq__': 'has_eq',
	'ULT': 'has_lt',
	'ULE': 'has_lt',
	'SLT': 'has_lt',
	'SLE': 'has_lt',
	'UGT': 'has_gt',
	'UGE': 'has_gt',
	'SGT': 'has_gt',
	'SGE': 'has_gt',
}

g_skip_op = ['BVV', 'BVS', 'If']

def walk_ast(expr, indent=4):
	# if not isinstance(expr, claripy.ast.Base):
	# 	return

	prefix = "  " * indent
	
	print(f"{prefix}Expr: {expr}")
	print(f"{prefix}  Op		: {expr.op}")
	print(f"{prefix}  Size	 : {expr.size()}")
	print(f"{prefix}  Symbolic : {expr.symbolic}")
	print(f"{prefix}  Leaf	 : {expr.is_leaf()}")
	print(f"{prefix}  Variables: {expr.variables}")
	print(f"{prefix}  Children : {len(expr.args)}")
	
	for i, child in enumerate(expr.args):
		print(f"{prefix}  Arg[{i}]:")
		if isinstance(child, claripy.ast.Base):
			walk_ast(child, indent + 2)
		else:
			print(f"{prefix}	{child}")

def init_feature_dict():
	features = {
		'has_and': False, 
		'has_or': False, 
		'has_add': False, 
		'has_sub': False,
		'has_xor': False, 
		'has_not': False, 
		'has_shl': False, 
		'has_shr': False, 
		'has_extract': False, 
		# 'has_concat': False, 
		'has_reverse': False,
		'has_ext': False, 
		'has_ne': False,
		'has_eq': False,
		'has_lt': False,
		'has_gt': False,
		'has_mul': False,

		'is_write_dst': False,
		'is_write_src': False,
		'is_write_len': False,
		'is_read_addr': False,
		'is_read_val': False,
		'is_read_len': False,
		# 'addr_code': False,
		'addr_data': False,
		'addr_stack': False,

		'compute_address': False,
		'in_cond': False, 
		'in_loop': False,
		'loop_ctrl': False,
		'data_in_cond': False,

		'is_single_use': False,
		'is_multi_use': False,
	}
	return features

def depends_on_sym(sym, expr):
	if not isinstance(expr, claripy.ast.Base):
		return False
	for v in expr.variables:
		if v == sym:
			return True
	return False

# def parse_expr(sym, expr):
# 	act = []

# 	if not isinstance(expr, claripy.ast.Base):
# 		return act

# 	def walk(e):
# 		op = e.op
# 		args = []
# 		record = False
# 		for i, child in enumerate(e.args):
# 			if depends_on_sym(sym, child):
# 				record = True
# 			else:
# 				args.append(child)

# 			if isinstance(child, claripy.ast.Base):
# 				walk(child)

# 		if record:
# 			act.append((op, args))

# 	walk(expr)
# 	return act

def parse_expr(self, expr):
	act = []

	if not isinstance(expr, claripy.ast.Base):
		return act

	def walk(e):
		op = e.op
		args = []
		for i, child in enumerate(e.args):
			args.append(child)

			if isinstance(child, claripy.ast.Base):
				walk(child)

		act.append((op, args))

	walk(expr)
	return act

def check_sec(secs, addr):
	for name, ranges in secs.items():
		for start, size in ranges:
			end = start + size
			if start <= addr < end:
				return name
	return None

def find_minimal_loop_units(seq, min_len=2):
	n = len(seq)
	loops = []
	MAX_LEN = 100

	for length in range(min_len, min(n // 2 + 1, MAX_LEN + 1)):
		i = 0
		while i + length <= n:
			unit = tuple(seq[i:i+length])
			repeat_count = 1
			j = i + length
			while j + length <= n and tuple(seq[j:j+length]) == unit:
				repeat_count += 1
				j += length
			if repeat_count >= 2:
				minimal_unit = unit
				for l in range(1, length):
					if length % l == 0:
						candidate = unit[:l]
						if candidate * (length // l) == unit:
							minimal_unit = candidate
							break
				loops.append((i, minimal_unit, repeat_count))
				i = j
			else:
				i += 1
	return loops


def preprocess_sequence(seq):
	priority = {
		'address_concretization': 5,
		'mem_write': 4,
		'mem_read': 3,
		'reg_write': 2,
		'tmp_write': 1,
		'constraint': 0
	}

	if not seq:
		return []

	result = []
	buffer = [seq[0]]

	for current in seq[1:]:
		last = buffer[-1]
		if current[0] == last[0] and current[1] == last[1]:
			buffer.append(current)
		else:
			result.extend(process_buffer(buffer, priority))
			buffer = [current]

	result.extend(process_buffer(buffer, priority))

	return result

def process_buffer(buffer, priority):
	if not buffer:
		return []

	addr, field = buffer[0][0], buffer[0][1]

	events = [e[2] for e in buffer]

	if all(e == 'tmp_write' for e in events):
		return [(addr, field, 'tmp_write')]

	constraint_events = set(e for e in events if e == 'constraint')
	result = [(addr, field, 'constraint')] if constraint_events else []

	other_events = [e for e in events if e != 'constraint']
	if other_events:
		highest = max(other_events, key=lambda x: priority.get(x, 0))
		result.append((addr, field, highest))

	return result

def seq_handler(instr_seq):
	loop_fields = []
	branch_fields = []

	processed = preprocess_sequence(instr_seq)
	# for item in processed:
	# 	 print(hex(item[0]), item[1], item[2])

	loops = find_minimal_loop_units(processed)

	# for item in loops:
	# 	min_loop = item[1]
	# 	for c in min_loop:
	# 		print(hex(c[0]), c[1], c[2])
	# ipdb.set_trace()

	for item in loops:
		min_seq = item[1]
		count = item[2]
		# ipdb.set_trace()
		for n in min_seq:
			event = n[2]
			field = n[1]
			if event == 'constraint':
				if field not in branch_fields:
					branch_fields.append(field)
			else:
				if field not in loop_fields:
					loop_fields.append(field)

	return loop_fields, branch_fields, processed

def count_field_usage_sequential(events):
	field_count = defaultdict(int)
	prev_field = None

	for item in events:
		field_name = item[1]
		if field_name != prev_field:
			field_count[field_name] += 1
			prev_field = field_name

	return field_count

def parse_expr_collection(expr_collection, secs, instr_seq, symbol_map):
	global g_op_mapping, g_skip_op
	ori_fields = list(symbol_map.values())
	field_feature = {}
	for action, val in expr_collection.items():
		# print(action)
		for field_name, exprs in val.items():
			# print("\t", field_name)
			if field_name not in field_feature:
				field_feature[field_name] = init_feature_dict()

			if action == 'address_concretization':
				field_feature[field_name]['compute_address'] = True

			if action == 'constraint':
				field_feature[field_name]['in_cond'] = True
				
			for item in exprs:
				addr = item[0]
				sym_name = item[1]
				flag = item[2]
				expr = item[3] 

				if flag & MEM_WRITE_DST:
					field_feature[field_name]['is_write_dst'] = True
				if flag & MEM_WRITE_SRC:
					field_feature[field_name]['is_write_src'] = True
				if flag & MEM_WRITE_LEN:
					field_feature[field_name]['is_write_len'] = True
				if flag & MEM_READ_ADDR:
					field_feature[field_name]['is_read_addr'] = True
				if flag & MEM_READ_VAL:
					field_feature[field_name]['is_read_val'] = True
				if flag & MEM_READ_LEN:
					field_feature[field_name]['is_read_len'] = True
				if flag & ADDR_DATA:
					field_feature[field_name]['addr_data'] = True
				if flag & ADDR_STACK:
					field_feature[field_name]['addr_stack'] = True

				# walk_ast(expr)
				act = parse_expr(sym_name, expr)
				cond_addrs = []
				for oper in act:
					op = oper[0]
					args = oper[1]
					use_sym = False
					for arg in args:
						if depends_on_sym(sym_name, arg):
							use_sym = True
							break

					if use_sym:
						if op in g_op_mapping:
							field_feature[field_name][g_op_mapping[op]] = True
						elif op == '__add__':
							is_sub = False
							for arg in args:
								if isinstance(arg, claripy.ast.Base) and arg.op == "BVV":
									bv_val = arg.args[0]
									if bv_val >= 2**(arg.size()-1):
										is_sub = True
							if is_sub:
								field_feature[field_name]['has_sub'] = True
							else:
								field_feature[field_name]['has_add'] = True
						else:
							if op not in g_skip_op:
								# print("!!", op, " not in mapping")
								pass
								# print(hex(addr), action, field_name, expr, op, args)
								# ipdb.set_trace()

				for addr in cond_addrs:
					sec = check_sec(secs, addr)
					if sec == 'stack' or sec == 'heap':
						ipdb.set_trace()
						# field_feature[field_name]['val_in_cond'] = True
						pass
					if sec == 'rodata' or sec == "rwdata":
						field_feature[field_name]['data_in_cond'] = True
					if sec == 'code':
						ipdb.set_trace()
						pass
						# field_feature[field_name]['code_in_cond'] = True

				# if action == 'constraint':
				# 	print(expr)

	loop_fields, branch_fields, processed_seq = seq_handler(instr_seq)
	for field in loop_fields:
		field_feature[field]['in_loop'] = True
	for field in branch_fields:
		field_feature[field]['loop_ctrl'] = True

	# for item in processed_seq:
	# 	print(hex(item[0]), item[1], item[2])

	# print(loop_fields)
	# print(branch_fields)
	field_count = count_field_usage_sequential(processed_seq)
	for key, val in field_count.items():
		print(key, val)
		if val == 1:
			field_feature[key]['is_single_use'] = True
		else:
			field_feature[key]['is_multi_use'] = True

	# for action, val in expr_collection.items():
	# 	for field_name, exprs in val.items():
	# 		for d in exprs:
	# 			sym_name = d[1]
	# 			expr = d[3] 
	# 			print(action, sym_name, expr)
	# ipdb.set_trace()

	return field_feature