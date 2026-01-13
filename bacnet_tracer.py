import os
import sys
import angr
import claripy
from simlib import *
import binascii
import ipdb

class BacnetReceiveProcedure(angr.SimProcedure):
    def __init__(self, tracer):
        super().__init__()
        self.packet = tracer.packet
        self.tracer = tracer

    def run(self, fd, buffer_addr):
        print('[BacnetReceiveProcedure]')
        for field in self.packet:
            print(field)

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

            packet_len += field_size

        self.tracer.skip_buffer.append([0x80BEB00, 0x5E4])
        print("[BacnetReceiveProcedure] packet len:", packet_len)
        len_concrete = claripy.BVV(packet_len, 32)

        mem_bv = self.state.memory.load(buffer_addr, packet_len)
        print(mem_bv)

        for c in self.state.solver.constraints:
            cs = str(c)
            print(cs)

        # ipdb.set_trace()
        self.tracer.start_flag = True
        self.state.regs.eax = len_concrete

start_addr = 0x8049AF2
end_addr = [
    0x8049B2C, # parse end
    0x808FD4D, # sendto
    0x808FFAA, # bip_send_pdu
    0x8080F3A,
]

recv_hook = {
    "symbol": {

    },
    "addr": {
        0x8049120: BacnetReceiveProcedure, # recvfrom
    }
}

hooks = {
    "symbol": {
        "debug_print_ipv4": RetTrueProcedure,
        "debug_print_string": RetTrueProcedure,
        "bbmd_address_match_self": RetFalseProcedure,
        "debug_printf_stdout": RetTrueProcedure,
        "debug_fprintf": RetTrueProcedure,
        "debug_printf_stderr": RetTrueProcedure,
        "debug_print_bip": RetTrueProcedure
    },
    "addr": {
        0x8049110: RetTrueProcedure,    # select
    }
}

memory_store = {
    0x8102440: binascii.unhexlify("0000000000000000c5cb080800000000cdcd0808000000007cc9080815ce080802cf0808fdc9080818d508080000000000000000000000006cd50808f2b90808779b080800000000000000007db50808000000007cab08080000000000000000000000000000000066af0808ceb30808a8bc080800000000a8c00808e2cf0808bdd2080856b10808000000000000000080ba0808000000000000000000000000000000000000000034c60808000000000000000020b7080800000000000000000000000000000000"), # handler
    0x80BEA98: binascii.unhexlify("01000000"), # socket fd
    0x80bf0e8: binascii.unhexlify("8198050820dd0b08000000000000000000000000000000000c0000000053696d706c6553657276657200000000000000") # Object_Table
}

binary = "./bacserv/bacserv"
packet_path = "./bacserv/bacnet.pdml"

key_funs = {
    0x80490B0: "memcpy",
    0x8049200: "memset",
    0x80491B0: "strlen",
    0x80492D0: "strtol",
    0x8049050: "strcmp",
    0x8049100: "memcmp",
    0x8049350: 'calloc',
    0x8049180: 'malloc',
    0x8049080: 'fflush',
    0x80492E0: 'fputs'
}