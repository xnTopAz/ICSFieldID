import os
import sys
import angr
import claripy
from simlib import *
import binascii
import struct
import ipdb


class MMSReceiveSymbolicProcedure(angr.SimProcedure):  # Hooked function: CotpConnection_readToTpktBuffer(pointer:cotpconnection)
    def __init__(self, tracer):
        super().__init__()
        self.packet = tracer.packet
        self.tracer = tracer

    def run(self, cotp_connection_pointer):
        print('CotpConnection_readToTpktBuffer() hooked!')
        print(cotp_connection_pointer)
        #input()
        messageReceived = 0x80575b4
        self.state.memory.store(claripy.BVV(0xc0000034, 32), claripy.BVV(messageReceived, 32), endness=self.state.arch.memory_endness)
        # print('Write concrete input!')
        # cotp_connection_pointer = 0x200000
        readbuffer_addr = 0xc000001c
        buffer_addr = 0xc001fd20
        #payload_addr = 0x204000
        #self.state.memory.store(cotp_connection_pointer + 0x30, claripy.BVV(payload_addr, 64), endness=self.state.arch.memory_endness)
        #self.state.memory.store(cotp_connection_pointer + 0x40, claripy.BVV(readbuffer_addr, 64), endness=self.state.arch.memory_endness)
        #self.state.memory.store(readbuffer_addr, claripy.BVV(buffer_addr, 64), endness=self.state.arch.memory_endness)
        buffer_size_addr = readbuffer_addr + 0x8
        packet_len = 0
        for field in self.packet:
            field_name = field['field_name']
            field_size = field['size']
            offset = field['offset']
            field_sym = claripy.BVS(field_name, field_size * 8)
            sym_name = next(iter(field_sym.variables))
            self.tracer.trace_symbols.append(sym_name)
            self.tracer.trace_symbol_map[sym_name] = field_name
            self.state.memory.store(buffer_addr + offset, field_sym)

            field_value = binascii.unhexlify(field['value'])
            field_bvv = claripy.BVV(field_value, field_size * 8)
            self.state.solver.add(field_sym == field_bvv)
            print(field_sym, field_bvv)
            # ipdb.set_trace()

            packet_len += field_size
        print("[MMSReceiveSymbolicProcedure] packet len:", packet_len)
        len_concrete = claripy.BVV(packet_len, 32)
        mem_bv = self.state.memory.load(buffer_addr, packet_len)
        print(mem_bv)
        for c in self.state.solver.constraints:
            cs = str(c)
            print(cs)
        self.tracer.start_flag = True
        # buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        # buffer = claripy.BVS('recv_data', 32 * 8)  # traffic_data_len bytes
        # len_concrete = claripy.BVV(32, 32)

        # self.state.memory.store(buffer_addr, buffer)
        self.state.memory.store(buffer_size_addr, len_concrete, endness=self.state.arch.memory_endness)
        #self.state.memory.store(payload_addr + 0xc, claripy.BVV(0, 32), endness=self.state.arch.memory_endness)
        #self.state.memory.store(payload_addr + 0x8, claripy.BVV(65000, 32), endness=self.state.arch.memory_endness)

        #self.state.globals['recv_data'] = buffer

        print('symbolic hooked')
        return 0

class InitProcedure(angr.SimProcedure):
    def run(self):
        self.call(
            0x806EDEA,
            [0x20000000, 0x20001000,1],
            "after_original"
        )
        return None
    def after_original(self,retval=None):
        self.jump(start_addr+3)

class TestProcedure(angr.SimProcedure):
    def run(self):
        print("[TestWrapper]")
        ipdb.set_trace()
        return

class MemcpyWrapper(angr.SimProcedure):
    def run(self, dst, src, size):
        print("[MemcpyWrapper]", dst, src, size)
        ipdb.set_trace()
        return angr.SIM_PROCEDURES['libc']['memcpy'].run(self, dst, src, size)

class CallocWrapper(angr.SimProcedure):
    def run(self, nmemb, size):
        print("[CallocWrapper]", nmemb, size)
        ipdb.set_trace()
        return angr.SIM_PROCEDURES['libc']['calloc'].run(self, nmemb, size)

class MallocWrapper(angr.SimProcedure):
    def run(self, size):
        print("[MallocWrapper]", size)
        ipdb.set_trace()
        return angr.SIM_PROCEDURES['libc']['malloc'].run(self, size)

class MemcmpWrapper(angr.SimProcedure):
    def run(self, p1, p2, size):
        print("[MemcmpWrapper]", p1, p2, size)
        ipdb.set_trace()
        return angr.SIM_PROCEDURES['libc']['memcmp'].run(self, p1, p2, size)

class StrlenWrapper(angr.SimProcedure):
    def run(self, p_str):
        print("[StrlenWrapper]", p_str)
        ipdb.set_trace()
        return angr.SIM_PROCEDURES['libc']['strlen'].run(self, p_str)


class StrcmpWrapper(angr.SimProcedure):
    def run(self, s1, s2):
        print("[StrcmpWrapper]", s1, s2)
        ipdb.set_trace()
        return angr.SIM_PROCEDURES['libc']['strcmp'].run(self, s1, s2)

start_addr = 0x0806DD13
end_addr = [
    0x806ED8C,0x0806DD1E
]

recv_hook = {
    "symbol": {
        "CotpConnection_readToTpktBuffer":MMSReceiveSymbolicProcedure,
    },
    "addr": {

    }
}

hooks = {
    "symbol": {
        "IsoConnection_callTickHandler": NoOpProcedure,
        "Handleset_waitReady": RetTrueProcedure,
        "Socket_getPeerAddress": NoOpProcedure,
        "Socket_getLocalAddress": NoOpProcedure,
        "IsoConnection_unlock": NoOpProcedure,
        "checkAuthentication": RetTrueProcedure,
    },
    "addr": {
        start_addr:InitProcedure,
        # 0x808c5f1:TestProcedure
        # 0x080492A0: MemcpyWrapper,
        # 0x80492f0: MemcmpWrapper,
        # 0x8049770: CallocWrapper,
        # 0x80493f0: MallocWrapper,
        # 0x08049480: StrlenWrapper,
        # 0x08049220: StrcmpWrapper,
    }
}

memory_store = {
    0x20000000:b"a"*100,
    0x20001000:b"b"*0x100
}

binary = "./mms/server_example_simple"
packet_path = "./mms/mms.pdml"

key_funs = {
    0x080492A0: "memcpy",
    0x080494F0: "memset",
    0x08049480: "strlen",
    0x08049700: "strtol",
    0x08049220: "strcmp",
    0x080492F0: "memcmp",
    0x080493F0: "malloc",
    0x08049770: "calloc",
    0x080493E0: "realloc"
}
