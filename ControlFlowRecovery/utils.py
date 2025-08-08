import ida_ida
import idaapi
import idc
import idautils
import ida_nalt


def get_extern_segment_info():
    for i in idautils.Segments():
        if idc.get_segm_name(i) == 'extern':
            extern_start_addr = idc.get_segm_start(i)
            extern_end_addr = idc.get_segm_end(i)
            return extern_start_addr, extern_end_addr

def get_min_max_addr():
    min_addr = ida_ida.inf_get_min_ea()
    max_addr = ida_ida.inf_get_max_ea()
    print(hex(min_addr), hex(max_addr))
    return min_addr, max_addr

def get_program_arch():
    
    if ida_ida.inf_is_64bit():
        bits = 64
    elif ida_ida.inf_is_16bit():
        bits = 16
    else:
        bits = 32

    try:
        is_be = ida_ida.inf_is_be()
    except:
        is_be = None
    endian = "big" if is_be else "little"
    return ida_ida.inf_get_procname(), bits, endian