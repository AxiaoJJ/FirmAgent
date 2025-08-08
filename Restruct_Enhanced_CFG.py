import idaapi
import idc
import idautils
import ida_auto
import ida_nalt
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ControlFlowRecovery import CreateFunction, utils, LocateCandidateFunctions

STRINGS_PATH = '/usr/bin/strings'
idc.auto_wait()

print(os.getcwd())
min_addr, max_addr = utils.get_min_max_addr()
arch, bits, endian = utils.get_program_arch()
file_path = ida_nalt.get_input_file_path()
file_name = ida_nalt.get_root_filename()

create_func_num = CreateFunction.create_function(arch, min_addr, max_addr)
print(file_path, file_name)
source_functions_list = LocateCandidateFunctions.my_run(STRINGS_PATH)
CreateFunction.get_functions_list(create_func_num, source_functions_list)
idc.qexit(0)


