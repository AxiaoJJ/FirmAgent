import idautils
import idaapi
import idc
import re

def list_library_functions():
    functions = []
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
            func_name = idc.get_func_name(funcea)
            if "nvram" in func_name.lower() and "set" in func_name.lower():
                functions.append((funcea, func_name))
    return functions

def find_function_calls(func_ea):
    xrefs = []
    for ref in idautils.CodeRefsTo(func_ea, 0):
        xrefs.append(ref)
    return xrefs

def addr2pseudo(cfunc, addr):
    item = cfunc.body.find_closest_addr(addr)
 
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        print("Not found item line")
    y = y_holder.value()
    return y


def get_arguments(func_ea):
    for _ in range(3):
        prev_addr = idc.prev_head(func_ea)
        prev_code = idc.generate_disasm_line(prev_addr, idc.GENDSM_FORCE_CODE)
        if "R0" in prev_code:
            return idc.get_strlit_contents(ida_bytes.get_dword(get_operand_value(prev_addr,1)), -1, 0)
        else:
            func_ea = prev_addr
    
    return None


def main():
    code_dict = {}
    functions = list_library_functions()
    for func_ea, func_name in functions:
        print(f"Function: {func_name} at {hex(func_ea)}")
        xrefs = find_function_calls(func_ea)
        for ref in xrefs:
            print(f"  Called at {hex(ref)}")
            if arg := get_arguments(ref):
                code_dict[hex(ref)] = arg
    print(code_dict)


if __name__ == "__main__":
    main()

# print(get_operand_value(0x18760,1))
# print(idc.get_strlit_contents(ida_bytes.get_dword(get_operand_value(0x18760,1)), -1, 0))