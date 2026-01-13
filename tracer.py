import sys
from multiprocessing.util import MAXFD

import angr
import archinfo
import claripy
from pandas import interval_range

from simlib import *
import ipdb

NOFLAG = 0
MEM_WRITE_DST = 0x1
MEM_WRITE_SRC = 0x2
MEM_WRITE_LEN = 0x4
MEM_READ_ADDR = 0x8
MEM_READ_VAL = 0x10
MEM_READ_LEN = 0x20
ADDR_CODE = 0x40
ADDR_DATA = 0x80
ADDR_STACK = 0x100


class SymTracer(object):

    def __init__(self, protocol_name, binary, lib, input_bytes=None, packet=None, start_addr=None, end_addr=None, recv_hook=None, hooks=None, memory_store=None, key_funs=None, start_state=None):

        self.protocol = protocol_name
        self.binary = binary
        self.lib = lib

        self.packet = packet

        self.start_addr = start_addr
        self.end_addr = end_addr

        self.recv_hook = recv_hook
        self.hooks = hooks

        self.memory_store = memory_store
        self.key_funs = key_funs

        self._proj = self.load_binary()
        self.secs = self.get_sections()
        self.instr_seq = []
        self.trace_symbol_map = {}
        self.trace_symbols = []
        self.seen_mem_read = []
        self.skip_buffer = []

        self.collect_expr = {"reg_write": {}, "mem_write": {}, "mem_read": {}, "tmp_write": {}, "constraint": {}, "address_concretization": {}}
        self.expr_set = set()

        self.start_state = start_state
        self.start_flag = False

    def is_global_addr(addr):
        for sec in main_obj.sections:
            if sec.name in ('.data', '.bss'):
                if sec.vaddr <= addr < sec.vaddr + sec.memsize:
                    return True
        return False

    @staticmethod
    def find_path_by_addr(state, addr):
        # print(state.regs.ip)
        if isinstance(addr, list):
            return state.solver.eval(state.regs.ip) in addr
        else:
            return addr == state.solver.eval(state.regs.ip)

    def load_binary(self):
        print(self.binary)
        proj = angr.Project(self.binary, auto_load_libs=False)
        print(proj)
        print("[+] mapped_base:", hex(proj.loader.main_object.mapped_base))
        return proj

    def get_sections(self):
        secs = {
            'code': [],
            'rodata': [], 
            'rwdata': [], 
        }
        for sec in self._proj.loader.main_object.sections:
            if '.text' == sec.name:
                secs['code'].append([sec.vaddr, sec.memsize])
            if '.rodata' == sec.name:
                secs['rodata'].append([sec.vaddr, sec.memsize])
            if '.data' == sec.name or '.bss' == sec.name:
                secs['rwdata'].append([sec.vaddr, sec.memsize])
        return secs

    def check_sec(self, addr):
        for start, size in self.skip_buffer:
            end = start + size
            if start <= addr < end:
                return None

        for name, ranges in self.secs.items():
            for start, size in ranges:
                end = start + size
                if start <= addr < end:
                    return name
        return None

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

    def get_addr_flag(self, state, expr):
        flag = NOFLAG
        addrs = []
        if expr.op == 'BVV':
            addrs.append(expr.concrete_value)
        else:
            act = self.parse_expr(expr)
            for oper in act:
                op = oper[0]
                args = oper[1]
                if op == 'BVV':
                    addrs.append(args[0])
                if op == "BVS":
                    param = args[0]
                    if 'ebp' in param:
                        flag |= ADDR_STACK
                    elif 'mem' in param:
                        # print("param", param)
                        # ipdb.set_trace()
                        flag |= ADDR_STACK

        for addr in addrs:
            sec = self.check_sec(addr)
            if sec == 'stack' or sec == "heap":
                flag |= ADDR_STACK
            if sec == 'rodata' or sec == "rwdata":
                flag |= ADDR_DATA
            if sec == 'code':
                # ipdb.set_trace()
                flag |= ADDR_CODE
        return flag

    def depends_on_target(self, expr):
        deps = []
        if not isinstance(expr, claripy.ast.Base):
            # print("[-][depends_on_target] not claripy.ast.Base", expr)
            return deps
        for v in expr.variables:
            if v in self.trace_symbols:
                deps.append(v)
        return deps

    def record_expr(self, action, addr, flag, deps, expr):
        if action not in self.collect_expr:
            return

        for dep in deps:
            field_name = self.trace_symbol_map[dep]
            # print("[record_expr]", action, hex(addr), flag, deps, expr)

            if field_name not in self.collect_expr[action]:
                self.collect_expr[action][field_name] = [(addr, dep, flag, expr)]
            else:
                self.collect_expr[action][field_name].append((addr, dep, flag, expr))

            self.instr_seq.append((addr, field_name, action))
            self.expr_set.add(expr)

    def walk_ast(self, expr, indent=4):
        prefix = "  " * indent
        
        print(f"{prefix}Expr: {expr}")
        print(f"{prefix}  Op       : {expr.op}")
        print(f"{prefix}  Size   : {expr.size()}")
        print(f"{prefix}  Symbolic : {expr.symbolic}")
        print(f"{prefix}  Leaf   : {expr.is_leaf()}")
        print(f"{prefix}  Variables: {expr.variables}")
        print(f"{prefix}  Children : {len(expr.args)}")
        
        for i, child in enumerate(expr.args):
            print(f"{prefix}  Arg[{i}]:")
            if isinstance(child, claripy.ast.Base):
                self.walk_ast(child, indent + 2)
            else:
                print(f"{prefix}    {child}")

    def address_concretization(self, state):
        addr_expr = state.inspect.mem_read_address

        leaf_bv = list(addr_expr.leaf_asts())
        symbol_recv_data = state.globals['recv_data']

    def symbolic_address_handler(self, state):
        symbolic_addr = state.inspect.address_concretization_expr
        action = state.inspect.address_concretization_action
        # print(symbolic_addr)
        leaf_bv = list(symbolic_addr.leaf_asts())
        symbol_recv_data = state.globals['recv_data']
        if self.found_symbol(symbol_recv_data, leaf_bv) and action =='store':
            # print('store to ', symbolic_addr)
            state.solver.add(symbol_recv_data == self.traffic_data)

    def create_state(self, start_addr):
        opts = {
            angr.options.SYMBOLIC,
            angr.options.LAZY_SOLVES,
            angr.options.UNDER_CONSTRAINED_SYMEXEC,
            angr.options.SYMBOLIC_WRITE_ADDRESSES,
            angr.options.TRACK_SOLVER_VARIABLES,
        }
        remove = {
            angr.options.SIMPLIFY_EXPRS,
            angr.options.AVOID_MULTIVALUED_READS,
            angr.options.AVOID_MULTIVALUED_WRITES,
            angr.options.CONSERVATIVE_READ_STRATEGY,
            angr.options.CONSERVATIVE_WRITE_STRATEGY,
            angr.options.SIMPLIFY_MEMORY_READS,
            angr.options.SIMPLIFY_MEMORY_WRITES,
            angr.options.SIMPLIFY_REGISTER_READS,
            angr.options.SIMPLIFY_REGISTER_WRITES,
            angr.options.UNICORN_AGGRESSIVE_CONCRETIZATION,
        }
        entry_state = self._proj.factory.blank_state(add_options=opts, remove_options=remove, addr=self.start_addr)
        return entry_state

    def on_reg_write(self, state):
        if not self.start_flag:
            return

        # if state.addr == 0x080933AF:
        #   ipdb.set_trace()

        reg_offset = state.inspect.reg_write_offset
        reg_length = state.inspect.reg_write_length
        expr = state.inspect.reg_write_expr
        # print(f"[on_reg_write] {reg_offset} {reg_length} {expr}")
        # print(self.trace_symbols)
        deps = self.depends_on_target(expr)
        if len(deps) > 0:
            # print("[on_reg_write]", hex(state.addr), len(deps), deps, expr)
            # self.walk_ast(expr)
            self.record_expr("reg_write", state.addr, NOFLAG, deps, expr)

    def on_mem_write(self, state):
        if not self.start_flag:
            return

        val_expr = state.inspect.mem_write_expr
        addr_expr = state.inspect.mem_write_address
        len_expr = state.inspect.mem_write_length

        if len_expr == None:
            return

        # print('[on_mem_write]', hex(state.addr))
        # if state.addr == 0x8049350:
        #   ipdb.set_trace()
        flag = NOFLAG
        flag |= self.get_addr_flag(state, addr_expr)

        # if flag != NOFLAG:
        #     print('[on_mem_write]', addr_expr, hex(flag))
        #     ipdb.set_trace()

        deps = self.depends_on_target(val_expr)
        if len(deps) > 0:
            # print("[on_mem_write][src]", hex(state.addr), len(deps), deps, val_expr)
            # self.walk_ast(val_expr)
            self.record_expr("mem_write", state.addr, flag | MEM_WRITE_SRC, deps, val_expr)

        deps = self.depends_on_target(addr_expr)
        if len(deps) > 0:
            # print("[on_mem_write][dst]", hex(state.addr), len(deps), deps, addr_expr)
            # self.walk_ast(addr_expr)
            self.record_expr("mem_write", state.addr, flag | MEM_WRITE_DST, deps, addr_expr)

        deps = self.depends_on_target(len_expr)
        if len(deps) > 0:
            # print("[on_mem_write][len]", hex(state.addr), len(deps), deps, len_expr)
            # self.walk_ast(len_expr)
            self.record_expr("mem_write", state.addr, flag | MEM_WRITE_LEN, deps, len_expr)

    def on_mem_read(self, state):
        if not self.start_flag:
            return

        val_expr = state.inspect.mem_read_expr
        addr_expr = state.inspect.mem_read_address
        len_expr = state.inspect.mem_read_length

        flag = NOFLAG
        flag |= self.get_addr_flag(state, addr_expr)

        # if flag != NOFLAG:
        #     print('[on_mem_read]', addr_expr, hex(flag))
        #     ipdb.set_trace()

        deps = self.depends_on_target(val_expr)
        if len(deps) > 0:
            # print("[on_mem_read][val]", hex(state.addr), len(deps), deps, val_expr)
            for dep in deps:
                mem_read_key = (state.addr, dep)
                if mem_read_key in self.seen_mem_read:
                    self.record_expr("mem_read", state.addr, flag | MEM_READ_VAL, deps, val_expr)
                else:
                    self.seen_mem_read.append(mem_read_key)
                    self.record_expr("mem_read", state.addr, flag, deps, val_expr)

        deps = self.depends_on_target(addr_expr)
        if len(deps) > 0:
            # print("[on_mem_read][addr]", hex(state.addr), len(deps), deps, addr_expr)
            # self.walk_ast(addr_expr)
            self.record_expr("mem_read", state.addr, flag | MEM_READ_ADDR, deps, addr_expr)

        deps = self.depends_on_target(len_expr)
        if len(deps) > 0:
            # ipdb.set_trace()
            # print("[on_mem_read][len]", hex(state.addr), len(deps), deps, len_expr)
            # self.walk_ast(len_expr)
            self.record_expr("mem_read", state.addr, flag | MEM_READ_LEN, deps, len_expr)

    def track_expr(self, state):
        if not self.start_flag:
            return

        expr = state.inspect.expr
        print("[track_expr]", expr, type(expr))

        deps = self.depends_on_target(expr)
        if len(deps) > 0:
            print("[track_expr]", len(deps), deps, expr)
            # self.walk_ast(len_expr)
            pass

    def on_tmp_write(self, state):
        if not self.start_flag:
            return

        # addr = state.addr

        tmp_expr = state.inspect.tmp_write_expr

        deps = self.depends_on_target(tmp_expr)
        if len(deps) > 0:
            # print("[on_tmp_write]", hex(state.addr), len(deps), deps, tmp_expr)
            # self.walk_ast(len_expr)
            self.record_expr("tmp_write", state.addr, NOFLAG, deps, tmp_expr)

    def on_call(self, state):
        if not self.start_flag:
            return

        esp = state.regs.esp
        ret_addr = state.memory.load(esp, 4, endness=state.arch.memory_endness)
        func_addr = state.inspect.function_address.concrete_value
        syscall_name = state.inspect.syscall_name
        print("[on_call] func addr:", hex(func_addr), syscall_name, ret_addr)

        if func_addr == 0x808DDC0:
            stack = state.memory

            arg1 = stack.load(esp + 4, 4, endness=state.arch.memory_endness)
            arg2 = stack.load(esp + 8, 4, endness=state.arch.memory_endness)
            arg3 = stack.load(esp + 0xc, 4, endness=state.arch.memory_endness)
            arg4 = stack.load(esp + 0x10, 4, endness=state.arch.memory_endness)
            print("Return address (caller PC):", ret_addr)
            print("Function call args:")
            print("arg1:", arg1)
            print("arg2:", arg2)
            print("arg3:", arg3)
            print("arg4:", arg4)
            ipdb.set_trace()

        if func_addr in self.key_funs:
            print("[!]", hex(func_addr), self.key_funs[func_addr])
            stack = state.memory

            arg1 = stack.load(esp + 4, 4, endness=state.arch.memory_endness)
            arg2 = stack.load(esp + 8, 4, endness=state.arch.memory_endness)
            arg3 = stack.load(esp + 0xc, 4, endness=state.arch.memory_endness)
            arg4 = stack.load(esp + 0x10, 4, endness=state.arch.memory_endness)
            print("Return address (caller PC):", ret_addr)
            print("Function call args:")
            print("arg1:", arg1)
            print("arg2:", arg2)
            print("arg3:", arg3)
            print("arg4:", arg4)
            ipdb.set_trace()
        # ipdb.set_trace()
        # args = state.calling_convention.get_args(state)
        # for idx, arg in enumerate(args):
        #   print("[on_call]", arg)

    def on_exit(self, state):
        if not self.start_flag:
            return

        guard = state.inspect.exit_guard
        if guard is None:
            return

        # print('[on_exit]', hex(state.addr), guard)
        # if state.addr == 0x8088504 or state.addr == 0x80884F7:
        #   ipdb.set_trace()
        
        deps = self.depends_on_target(guard)
        if len(deps) > 0:
            # print("[on_exit]", hex(state.addr), guard)
            # self.walk_ast(len_expr)
            self.record_expr("constraint", state.addr, NOFLAG, deps, guard)

    def on_address_concretization(self, state):
        if not self.start_flag:
            return

        symbolic_addr = state.inspect.address_concretization_expr
        action = state.inspect.address_concretization_action

        deps = self.depends_on_target(symbolic_addr)
        if len(deps) > 0:
            # print("[on_address_concretization]", hex(state.addr), deps, symbolic_addr, action)
            # self.walk_ast(len_expr)
            self.record_expr("address_concretization", state.addr, NOFLAG, deps, symbolic_addr)

    def analysis(self):
        # entry_state = self.create_state(self.start_addr)
        entry_state = self._proj.factory.blank_state(addr=self.start_addr)

        stack_size = 0x200000
        sp = entry_state.regs.sp.concrete_value
        stack_min = sp - stack_size
        stack_base = sp 
        self.secs['stack'] = [[stack_min, stack_size]]

        heap_base = entry_state.heap.heap_base
        heap_size = entry_state.heap.heap_size
        self.secs['heap'] = [[heap_base, heap_size]]

        entry_state.inspect.b('mem_read', when=angr.BP_AFTER, action=self.on_mem_read)
        entry_state.inspect.b('mem_write', when=angr.BP_AFTER, action=self.on_mem_write)
        entry_state.inspect.b('reg_write', when=angr.BP_AFTER, action=self.on_reg_write)
        entry_state.inspect.b('tmp_write', when=angr.BP_AFTER, action=self.on_tmp_write)
        entry_state.inspect.b('exit', when=angr.BP_BEFORE, action=self.on_exit)
        entry_state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=self.on_address_concretization)
        # entry_state.inspect.b('expr', when=angr.BP_AFTER, action=self.track_expr)
        # entry_state.inspect.b('call', when=angr.BP_BEFORE, action=self.on_call)

        simgr = self._proj.factory.simgr(entry_state, save_unconstrained=True)
        dfs_t = angr.exploration_techniques.DFS(deferred_stash="deferred")
        simgr.use_technique(dfs_t)

        print(self.hooks)
        for sym, proc in self.hooks['symbol'].items():
            symbol = self._proj.loader.find_symbol(sym)
            print(symbol)
            if symbol:
                addr = symbol.rebased_addr
                print("[+] sym:", sym, hex(addr))
                self._proj.hook(addr, proc())
            else:
                print(f"{sym} not found")

        for addr, proc in self.hooks['addr'].items():
            self._proj.hook(addr, proc())

        print(self.memory_store)
        for addr, mem in self.memory_store.items():
            print(addr, mem)
            entry_state.memory.store(addr, mem, size=len(mem))

        print(self.recv_hook)
        for sym, proc in self.recv_hook['symbol'].items():
            addr = self._proj.loader.find_symbol(sym).rebased_addr
            self._proj.hook(addr, proc(self))

        for addr, proc in self.recv_hook['addr'].items():
            self._proj.hook(addr, proc(self))

        for addr, symbol in self.key_funs.items():
            self._proj.hook(addr, angr.SIM_PROCEDURES['libc'][symbol]())
            print(hex(addr), symbol)

        print("[+] Trace symbol:", self.trace_symbols)

        found_state_num = 0
        flag = True
        debug_flag = 1
        hooked_flag = 0

        while simgr.active:
            if not flag:
                break
            simgr.step()
            st = simgr.active[0]
            addr = st.addr
            # if self.start_flag:
            #     print(hex(addr))

            # if addr == 0x808DE08:
            #     ipdb.set_trace()

            if simgr.unconstrained:
                for unconstrained_state in simgr.unconstrained:
                    print('unconstrained_state jump_source: {}'.format(unconstrained_state.history.jump_source))
                    # jump the icall
                    next_state_addr = unconstrained_state.callstack.ret_addr
                    unconstrained_state.regs.ip = claripy.BVV(next_state_addr, 8 * 8)
                    # recover the callstack
                    unconstrained_state.callstack = unconstrained_state.callstack.next
                    print(unconstrained_state.regs.ip)
                    simgr.move(from_stash='unconstrained', to_stash='active')

            for state in simgr.active:
                if self.find_path_by_addr(state, self.end_addr):
                    print("[+] end")
                    # ipdb.set_trace()
                    flag = False
                    # for c in state.solver.constraints:
                    #     cs = str(c)
                    #     print(cs)
                    break

        return self.collect_expr