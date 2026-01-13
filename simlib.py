import angr
import claripy
import ipdb

class NoOpProcedure(angr.SimProcedure):
    def run(self, s):
        return

class RetFalseProcedure(angr.SimProcedure):
    def run(self):
        return 0

class RetTrueProcedure(angr.SimProcedure):
    def run(self):
        return 1

class RetMinusProcedure(angr.SimProcedure):
    def run(self):
        return -1

class TestProcedure(angr.SimProcedure):
    def run(self, pointer):
        print(pointer)
        return