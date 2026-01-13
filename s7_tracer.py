import os
import sys
import angr
import claripy
from simlib import *
import binascii
import struct

class OperatorNew(angr.SimProcedure):
    def __init__(self, project=None, cc=None, prototype=None):
        super().__init__(project=project, cc=cc, prototype=prototype)
        self.is_array = False
        
    def run(self, size):
        addr = self.state.heap._malloc(size)
        
        # Track allocation
        if not hasattr(self.state, 'cpp_allocations'):
            self.state.cpp_allocations = {}
        self.state.cpp_allocations[addr] = ('object', size)
        
        # Return address in eax
        return addr


class InitProcedure(angr.SimProcedure):
    def run(self):
        print(self.state.solver.eval(self.state.regs.eax))
        self.state.regs.esp -= 4
        self.state.memory.store(self.state.regs.esp,self.state.regs.eax,endness='Iend_LE')#socket
        self.state.regs.esp -= 4
        self.state.memory.store(self.state.regs.esp,claripy.BVV(0, 32),endness='Iend_LE')#ret    
        self.jump(0x08051104)
       
class S7ReceiveProcedure(angr.SimProcedure):
    def __init__(self, tracer):
        super().__init__()
        self.packet = tracer.packet
        self.tracer = tracer
        self.field_list = []
        for field in self.packet:
            field_name = field['field_name']
            field_size = field['size']
            field_offset = field['offset']
            field_sym = claripy.BVS(field_name, field_size * 8)
            sym_name = next(iter(field_sym.variables))
            field_value = binascii.unhexlify(field['value'])
            field_bvv = claripy.BVV(int.from_bytes(field_value, 'big'), field_size * 8)
            self.field_list.append((field_name,field_offset,field_size,field_sym,sym_name,field_bvv))
    def run(self,this,bv_pdu,bv_length):
        pdu = self.state.solver.eval(bv_pdu)
        length = self.state.solver.eval(bv_length)
        if "received_len" not in self.state.globals:
            self.state.globals["received_len"] = 0 
        print(f"[S7ReceiveProcedure] pdu {hex(pdu)} length {hex(length)} from {self.state.globals['received_len']}")
        offset = 0
        for field_name,field_offset,field_size,field_sym,sym_name,field_bvv in self.field_list:
            if field_offset >= self.state.globals["received_len"] and field_offset + field_size <= self.state.globals["received_len"] + length:
                print(f"recv {field_name} {field_bvv}")
                self.tracer.trace_symbols.append(sym_name)
                self.tracer.trace_symbol_map[sym_name] = field_name
                self.state.memory.store(pdu + offset, field_sym)
                self.state.solver.add(field_sym == field_bvv)
                offset += field_size
        
        self.state.globals["received_len"] += offset
        self.tracer.start_flag = True
        #input()
        return


start_addr = 0x08049553
end_addr = [
    0x08049600,0x08049667,0
]

recv_hook = {
    "symbol": {
        
    },
    "addr": {
        0x080665DC:S7ReceiveProcedure,#TMsgSocket::RecvPacket
    }
}

hooks = {
    "symbol": {
        "_Znwj": OperatorNew,
    },
    "addr": {
        0x08049290:OperatorNew,
        0x08065CFE:RetTrueProcedure,#canread
        0x0805155C:NoOpProcedure,#doevent
        #0x0804E235:TestProcedure,
        #0x0804E23A:TestProcedure,
        #0x080516B6:TestProcedure,
        0x0804BB2D:InitProcedure,
    }
}

memory_store = {
}

binary = "./s7/server_s7"
packet_path = "./s7/s7.pdml"

key_funs = {
}
