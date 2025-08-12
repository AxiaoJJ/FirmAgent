#coding=gbk
import idaapi
import idautils
import idc

def op_constant(op,expr=None):
    if op == idaapi.cot_obj and expr is not None:  
        obj = expr.obj_ea
        seg = idaapi.getseg(obj)
        seg_name = idaapi.get_segm_name(seg)
        if seg_name == '.rodata' or seg_name == ".rdata" or seg_name == "LOAD":  
            return True
        else:
            return False
    elif op == idaapi.cot_ref and expr is not None:    
        return op_constant(expr.x.op, expr.x)
    
    return op == idaapi.cot_num or op == idaapi.cot_fnum or op == idaapi.cot_str

def arg_constant(cfunc,address):
    item = cfunc.body.find_closest_addr(address)
    expr = item.cexpr
    try:
        name = idc.get_func_name(expr.x.obj_ea)
        if name in ["CsteSystem", "system", "doSystemCmd", "twsystem", "doSystem", "popen", "execv", "execve", "FCGI_popen", "rut_doSystemAction", "_system"]:                   
            if expr.op == idaapi.cot_call:

                arg_size = expr.a.size()
                for i in range(arg_size):
                    if expr.a[i].op == idaapi.cot_cast:
                        if op_constant(expr.a[i].x.op, expr.a[i].x):
                            continue
                        else:
                            return True
                    else:
                        if op_constant(expr.a[i].op, expr.a[i]):
                            continue
                        else:
                            return True
            else:
                print(f'This sink point not analysis:{hex(address)}')
                
        elif name in ["strcpy", "cmsUtl_strcpy", "strcat"]:
            if expr.op == idaapi.cot_call:

                if expr.a[1].op == idaapi.cot_cast:
                    if op_constant(expr.a[1].x.op, expr.a[1].x):
                        pass
                    else:
                        return True
                else:
                    if op_constant(expr.a[1].op, expr.a[1]):
                        pass
                    else:
                        return True
            else:
                print(f'This sink point not analysis:{hex(address)}')
                
        elif name in ["sscanf"]:
            if expr.op == idaapi.cot_call:

                if expr.a[0].op == idaapi.cot_cast:
                    if op_constant(expr.a[0].x.op, expr.a[0].x):
                        pass
                    else:
                        return True
                else:
                    if op_constant(expr.a[0].op, expr.a[0]):
                        pass
                    else:
                        return True
            else:
                print(f'This sink point not analysis:{hex(address)}')
                
                
        elif name in ["sprintf"]:
            if expr.op == idaapi.cot_call:

                arg_size = expr.a.size()
                for i in range(2, arg_size):
                    if expr.a[i].op == idaapi.cot_cast:
                        if op_constant(expr.a[i].x.op, expr.a[i].x):
                            continue
                        else:
                            return True
                    else:
                        if op_constant(expr.a[i].op, expr.a[i]):
                            continue
                        else:
                            return True
                
        else:
            return True                  
    except Exception as e:
        print(e, hex(address))

def find_sink_xrefs(sinks):

    for sink_name in sinks:
        sink_ea = idc.get_name_ea_simple(sink_name)
        if sink_ea == idaapi.BADADDR:
            print(f"[-] Sink function '{sink_name}' not found in the binary.")
        
        for xref in idautils.CodeRefsTo(sink_ea, 0):
            func_start = idc.get_func_attr(xref, idc.FUNCATTR_START)
            if func_start == idaapi.BADADDR:
                print(f"[-] Failed to determine function boundaries for xref at 0x{xref:X}. Skipping...")
                continue
            
            func = idaapi.get_func(xref)
            if func is None:
                print(f"addr {hex(xref)} no exist")
            else:
                cfunc = idaapi.decompile(func)
                if cfunc is not None:
                    if(arg_constant(cfunc,xref)):
                        if func_start not in results:
                            results[func_start] = xref
                        else:
                            results[func_start] = max(results[func_start], xref)


results = {}
ci_sinks_name = ["CsteSystem","system", "_system", "doSystemCmd", "twsystem", "doSystem", "popen", "execv", "execve",
                                    "FCGI_popen", "rut_doSystemAction"]
bof_sink_name = ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "sscanf", "cmsUtl_strcpy"]

find_sink_xrefs(ci_sinks_name)


results_ci = results
results = {}    
find_sink_xrefs(bof_sink_name)

print('ci sink func:')
with open('sink_addr.txt','w') as file:
    for key,value in results_ci.items():
        line = f'0x{key:X}..0x{value:X},'
        file.write(line)
        print(line, end='') 
        
print('\nbof sink func:')
with open('sink_addr.txt','a') as file:
    for key,value in results.items():
        line = f'0x{key:X}..0x{value:X},'
        file.write(line)
        print(line, end='')
    file.seek(file.tell()-1, 0)
    file.truncate()   