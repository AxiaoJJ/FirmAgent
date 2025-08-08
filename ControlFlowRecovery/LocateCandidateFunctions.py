#coding=gbk
import idautils
import idc
import idaapi
import ida_nalt
import os
import subprocess
import sys
from ida_search import SEARCH_DOWN, SEARCH_UP
from ida_idaapi import BADADDR
from ControlFlowRecovery import utils
import ida_bytes

print(sys.path)

black_source_function_name = ["strncmp", "strcmp", "memset", "nvram_set", "json_object_object_add", "fprintf",
                             "printf", "cprintf", "setenv", "fputs", "unlink", "strstr", "sprintf", "snprintf",
                             "uci_set_option", "log_log", "system", "doSystemCmd", "strcasestr", "log_debug_print",
                             "memcpy", "SetValue", "syslog", 'ipv6_nvname', 'json_object_new_string','nvram_contains_word',
                             'nvram_unset', 'nvram_get_int', 'fread', 'read', 'getenv', 'puts', 'strcpy', 'setWanValue','atoi',
                             'fopen', 'strcasecmp']

white_source_function_name = ["websGetVar", "j_websGetVar", "webGetVarN", "websGetVarN", "webGetVar", 
                              "webGetVarString","websGetVarString", "getcgi", 
                              "cmsObj_get", "cJSON_GetObjectItemCaseSensitive", "cJSON_GetObject", 
                              "nvram_get_like", 'nvram_get', 'nvram_default_get', 'GetValue', 'acosNvramConfig_get']

arm_jump_insn_ops = ['B', 'BL']
mips_jump_insn_ops = ['jalr', 'j', 'jr']
la_op_value = BADADDR

def check_strs_in_bin(all_strs:list, bin_path:str, strings_path:str)->list:
    filter_strs = []
    os_command = strings_path + " " + "-n" + " " + "4" + " " + bin_path
    process = subprocess.Popen(args=os_command, errors=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    strings_result = stdout.decode('utf-8', errors='ignore')

    for str in all_strs:
        if str in strings_result:
            filter_strs.append(str)
    
    return filter_strs

def find_nearest_la_instruction(jalr_ea):
    prev_ea = jalr_ea
    for i in range(10):
        prev_ea = idc.prev_head(prev_ea)
        insn_operator = idc.print_insn_mnem(prev_ea)
        if insn_operator == 'la':
            jump_addr = idc.get_operand_value(prev_ea, 1)
            return jump_addr
    return BADADDR

def find_jump_addr_within_arch(now_addr, arch)->int:
    #insn = idc.generate_disasm_line(now_addr, 0)
    insn_operator = idc.print_insn_mnem(now_addr)
    global la_op_value 

    if arch == 'ARM':
        if insn_operator in arm_jump_insn_ops:
            jump_addr = idc.get_operand_value(now_addr, 0)
        else:
            jump_addr = BADADDR
    
    elif arch == 'mipsl' or arch == 'mipsb':
        if insn_operator == 'jalr':
            jump_addr = find_nearest_la_instruction(now_addr)

        # elif insn_operator == 'la':
        #     la_op_value = idc.get_operand_value(now_addr, 1)
        #     jump_addr = BADADDR
        
        elif insn_operator == 'bal':
            jump_addr = idc.get_operand_value(now_addr, 0)

        elif insn_operator == 'jal':
            jump_addr = idc.get_operand_value(now_addr, 0)

        else:
            jump_addr = BADADDR
        
    else:
        jump_addr = BADADDR
    
    #print(arch, insn_operator, len(insn_operator), hex(jump_addr))
    return jump_addr


def get_candidate_source_functions(strs_addrs:list)->list:
    
    target_function_addrs = []
    arch, bits, endian = utils.get_program_arch()
    count = 0

    for str_addr in strs_addrs:
        func = idaapi.get_func(str_addr)
        global la_op_value
        la_op_value = BADADDR
        if func:
            fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)          #获取函数流程图，得到每个基本块(ida框图中的基本块)
            count += 1
            for block in fc:
                b_start = block.start_ea
                b_end = block.end_ea        
                if str_addr > b_start and str_addr < b_end:             #找出包含字符串的基本块
                    now_addr = str_addr
                    # print("-------------------------------------------")
                    # print("now_addr is {0}, basic block end addr is {1}".format(hex(now_addr), hex(b_end)))
                    if arch == 'mipsl' or arch == 'mipsb':
                        prev_addr = idc.prev_head(now_addr)
                        insn = idc.print_insn_mnem(prev_addr)
                        if insn in ['jal', 'bal']:
                            target_function_addrs.append(idc.get_operand_value(prev_addr, 0))
                            break
                        elif insn == 'jalr':
                            while(prev_addr > b_start):
                                prev_addr = idc.prev_head(prev_addr)
                                insn = idc.print_insn_mnem(prev_addr)
                                if insn == 'la':
                                    target_function_addrs.append(idc.get_operand_value(prev_addr, 1))
                                    break
                            
                        else:
                            while(True):
                                jump_addr = find_jump_addr_within_arch(now_addr, arch)  
                                if jump_addr != BADADDR:
                                    target_function_addrs.append(jump_addr)
                                    break
                                now_addr = idc.next_head(now_addr)   
                                
                    elif arch == 'ARM':            
                        while(now_addr < b_end):
                            jump_addr = find_jump_addr_within_arch(now_addr, arch)          #找到最近的跳转指令
                            if jump_addr != BADADDR:
                                target_function_addrs.append(jump_addr)
                                break

                            now_addr = idc.next_head(now_addr)           
                    break
    print(f"all_func count is: {count}, found string_func count is: {len(target_function_addrs)}")    
    return target_function_addrs

def Get_Valid_Segment():
    Valid_Segments = []
    
    Valid_Segments_Name = ['LOAD', '.text']
    for seg in idautils.Segments():
        Segments_Scope = []
        if idc.get_segm_name(seg) in Valid_Segments_Name:
            Segments_Scope.append(seg)
            Segments_Scope.append(idc.get_segm_end(seg))
            Valid_Segments.append(Segments_Scope)
    return Valid_Segments

def get_strs_refs_addrs(filter_strs)->list:

    min_addr, max_addr = utils.get_min_max_addr()
    all_strs_refs_addrs = []
    
    for single_str in filter_strs:
        str_refs_in_code_addrs = srch_str_addr_in_seg(single_str, min_addr, max_addr)       #从二进制文件的代码段中获取指定字符串的引用地址
        for str_refs_in_code_addr in str_refs_in_code_addrs:
            all_strs_refs_addrs.append(str_refs_in_code_addr)
    
    return all_strs_refs_addrs

def save_strs_refs_addrs(saved_addrs, log_file_name):
    with open(log_file_name, "w+") as log_file:
        for addr in saved_addrs:
            log_file.write(hex(addr))
            log_file.write("\n")

def Read_Strs_Refs_Addrs_From_File(log_file_name):
    valid_addrs = []
    with open(log_file_name, 'r+') as log_file:
        addrs =log_file.readlines()
        for addr in addrs:
            valid_addr = addr.strip("\n")
            valid_addrs.append(int(addr, 16))
    return valid_addrs

def srch_str_addr_in_seg(now_str:str, start_addr, end_addr)->list:
    cur_addr = start_addr
    str_used_in_code_addrs = []

    # print("now string is", now_str)
    hex_str = str.encode(now_str).hex()
    #print("now hex string is", h)
    pattern = "".join([content + " " if index % 2 else content for index, content in enumerate(hex_str)])

    while cur_addr < end_addr:
        cur_addr = idc.find_bytes(pattern, cur_addr, radix=16)

        if cur_addr == BADADDR:
            continue
        else:
            addr_flag = idc.get_full_flags(cur_addr)
            if idc.is_code(addr_flag):                      #字符串直接位于代码中
                # print("find in ", hex(cur_addr))
                if cur_addr not in str_used_in_code_addrs:
                    str_used_in_code_addrs.append(cur_addr)         #在程序中的地址
                else:
                    break
            else:
                data_refs_cur_addrs = idautils.DataRefsTo(cur_addr)         #引用字符串的地址
                for addr in data_refs_cur_addrs:
                    # print(hex(addr))
                    if addr not in str_used_in_code_addrs:
                        str_used_in_code_addrs.append(addr) 

        cur_addr =idc.next_head(cur_addr)
    return str_used_in_code_addrs
    """
    ### Searching by the text, duplicating
    while cur_addr < end_addr:
        cur_addr = idc.find_text(cur_addr, SEARCH_DOWN, 0xD7790, 0, str)
        if cur_addr == BADADDR:
            continue
        else:
            addr_flag = idc.get_full_flags(cur_addr)
            if idc.is_code(addr_flag):
                print("find in ", hex(cur_addr))
                if cur_addr not in str_used_in_code_addrs:
                    str_used_in_code_addrs.append(cur_addr) 
                else:
                    break

        cur_addr =idc.next_head(cur_addr)
    """

def get_matching_strings_addrs(orgin_strs:str, file_path:str, strings_path:str)->list:
    split_strs = orgin_strs.split(" ")
    file_name = file_path.split("\\")[-1]
    log_file_name = file_name + "_para_results.txt"

    filter_strs = check_strs_in_bin(split_strs, file_path, strings_path)
    print(filter_strs)
    print("filter str number is {0}, orgin str number is {1}".format(len(filter_strs), len(split_strs)))
    strs_ref_addrs = get_strs_refs_addrs(filter_strs)
    save_strs_refs_addrs(strs_ref_addrs, log_file_name)

    return strs_ref_addrs

def filter_source_functions_with_name(source_functions_frequency:list)->list:
    filter_source_functions = []
    # element= (func_addr, frequency)
    for element in source_functions_frequency:
        func_name = idc.get_func_name(element[0])
        if func_name in white_source_function_name:
            filter_source_functions.append(element[0])
            continue

        if func_name in black_source_function_name or element[1] <= 2:
            continue

        filter_source_functions.append(element[0])
    
    for func_start_addr in idautils.Functions():
        func_name = idc.get_func_name(func_start_addr)
        if func_name in white_source_function_name and func_name not in filter_source_functions:
            filter_source_functions.append(func_start_addr)

    print(list(map(hex,filter_source_functions)), len(filter_source_functions))
    return filter_source_functions
    

# def filter_source_functions_with_name(source_functions_frequency:list)->list:
#     filter_source_functions = []
#     # element= (func_addr, frequency)
#     for element in source_functions_frequency:
#         func_name = idc.get_func_name(element[0])
#         if func_name in black_source_function_name:              #对黑名单中的函数进行过滤
#             print(f"filter func_name:{func_name}")
#             continue
#         else:
#             filter_source_functions.append(element[0])

#     for func_start_addr in idautils.Functions():
#         func_name = idc.get_func_name(func_start_addr)
#         if func_name in white_source_function_name and func_name not in filter_source_functions:
#             filter_source_functions.append(func_start_addr)

#     print(list(map(hex,filter_source_functions)), len(filter_source_functions))
#     return filter_source_functions

def get_source_functions(*args, **kwargs)->list:
    strs_addrs_list:list = kwargs.get("strs_addrs_list", [])
    strs_addrs_file = kwargs.get("strs_addrs_file", "")

    if len(strs_addrs_list)!=0:
        strs = strs_addrs_list
    
    if strs_addrs_file!="":
        strs = Read_Strs_Refs_Addrs_From_File(strs_addrs_file)    #获取所有字符串及其数据引用的地址
    
    candidate_source_functions  = get_candidate_source_functions(strs)
    candidate_source_functions_dict = {}
    for key in candidate_source_functions:
        candidate_source_functions_dict[key] = candidate_source_functions_dict.get(key, 0) + 1
    
    source_function_frequency = sorted(candidate_source_functions_dict.items(),key=lambda x:x[1], reverse=True)
    print("Candidate source functions with frequency are:\n")
    print(source_function_frequency)

    #return None
    return filter_source_functions_with_name(source_function_frequency)

def read_orgin_strs(file_path):
    orgin_strs_file = file_path + '_origin_strs.txt'
    with open(orgin_strs_file, "r+") as org_str_file:
        org_strs = org_str_file.read()
        return org_strs

def my_run(strings_path:str):
    now_file_name = ida_nalt.get_root_filename()
    now_file_path = ida_nalt.get_input_file_path()
    org_strs = read_orgin_strs(now_file_path)
    print(org_strs)
    
    if org_strs != "":
        strs_addrs = get_matching_strings_addrs(org_strs, now_file_path, strings_path)
        print(strs_addrs)
        source_functions_list = get_source_functions(strs_addrs_list=strs_addrs)
        return source_functions_list




