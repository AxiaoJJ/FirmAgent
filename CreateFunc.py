import idaapi
import idc
import idautils
import ida_auto
import ida_nalt
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ControlFlowRecovery import CreateFunction, utils, LocateCandidateFunctions

idc.auto_wait()

print(os.getcwd())
min_addr, max_addr = utils.get_min_max_addr()
arch, bits, endian = utils.get_program_arch()

create_func_num = CreateFunction.create_function(arch, min_addr, max_addr)
idc.qexit(0)