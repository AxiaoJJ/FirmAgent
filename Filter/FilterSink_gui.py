import ida_name
import idautils
import ida_hexrays
import ida_funcs
import idc
import ida_ua
import ida_idp
import ida_nalt
import ida_xref
import ida_bytes
import networkx as nx
from collections import deque
import csv
import re
import idaapi

sink_function=['strcpy','sscanf','sprintf','popen',"CsteSystem", "system", '_system', "doSystemCmd", "twsystem", "doSystem"]    
type_3_list=['strcpy','memcpy']

DEBUG=False

def is_inBlock(ea, start, end):  
    if ea >= start and ea < end:
        return True
    else:
        return False

def get_block_succs(blocks):  
    succs = []
    for i in range(len(blocks)):
        succs.append([])

    for i in range(len(blocks)):
        bb_start = blocks[i][0]
        refs = idautils.CodeRefsTo(bb_start, 1)      
        
        for ref in refs:
            for j in range(len(blocks)):
                if is_inBlock(ref, blocks[j][0], blocks[j][1]):
                    succs[j].append(i)
    return succs

def trace_blocks(graph,start,depth):   
    paths=[]
    queue=deque([([start], 0)])
    if start==0:
        paths.append([0])
        return paths
    while queue:
        path, current_depth = queue.popleft()
        current_node = path[-1]
        if current_depth == depth or not list(graph.predecessors(current_node)):
            paths.append(path[::-1])
            continue
        for next_node in graph.predecessors(current_node):
            if next_node not in path:
                new_path = list(path)  
                new_path.append(next_node)
                queue.append((new_path, current_depth + 1))   
    return paths

def stack_variable_defination(func_code_list,number,variable):   
    for i in range(0,number):
        if variable in func_code_list[i]:
            def_end_number=len(func_code_list[i])
            if '//' in func_code_list[i]:
                def_end_number=func_code_list[i].find('//')
            arrays_pattern=re.compile(r'\[(\d+)\]')                
            arrays_length=arrays_pattern.findall(func_code_list[i][:def_end_number])
            if len(arrays_length)==1:
                return int(arrays_length[0])
            else:
                return 0
    return 0

def variable_filter(arg):         
    variable_address = idc.get_name_ea_simple(arg)        
    if variable_address == idc.BADADDR:
        return True    
    else:
        return False   

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
        if expr.x.op ==  idaapi.cot_idx and expr.x.x.op ==idaapi.cot_obj: 
            return True
        else:
            return False
    
    return op == idaapi.cot_num or op == idaapi.cot_fnum or op == idaapi.cot_str

def FilterConstant(address):         
    try:
        # Get function containing the address
        func = idaapi.get_func(address)
        if not func:
            print(f"Cannot get function for address {hex(address)}")
            return True
            
        cfunc = idaapi.decompile(func.start_ea)
        if not cfunc:
            print(f"Cannot decompile function at {hex(address)}")
            return True
            
        item = cfunc.body.find_closest_addr(address)
        expr = item.cexpr
            
        name = idc.get_func_name(expr.x.obj_ea)
        if not name:
            return True
        
        # Analyze different function types
        if name in ["system", '_system', "popen"]:   
            if expr.op == idaapi.cot_call:                
                input_arg = expr.a[0]
                if input_arg.op == idaapi.cot_cast:
                    if not op_constant(input_arg.x.op, input_arg.x):
                        return True  # Keep this sink (dangerous)
                else:
                    if not op_constant(input_arg.op, input_arg):
                        return True  # Keep this sink (dangerous)
            else:
                return False  # Filter out (all args are constants)
        
        elif name in ["CsteSystem", "doSystemCmd", "twsystem", "doSystem"]:   
            if expr.op == idaapi.cot_call:                
                arg_size = expr.a.size()
                for i in range(arg_size):
                    arg_expr = expr.a[i]
                    if arg_expr.op == idaapi.cot_cast:
                        if not op_constant(arg_expr.x.op, arg_expr.x):
                            return True  # Keep this sink (dangerous)
                    else:
                        if not op_constant(arg_expr.op, arg_expr):
                            return True  # Keep this sink (dangerous)
                return False
            else:
                return False
                
        elif name in ["strcpy"]:
            if expr.op == idaapi.cot_call:
                dest_arg = expr.a[0]
                if dest_arg.op != idaapi.cot_var:    # dest is not a variable (Filter)
                    return False
                    
                src_arg = expr.a[1]
                if src_arg.op == idaapi.cot_cast:
                    is_const = op_constant(src_arg.x.op, src_arg.x)
                else:
                    is_const = op_constant(src_arg.op, src_arg)
                    
                if is_const:
                    return False  # Filter out (constant source)
                else:
                    return True   # Keep this sink (dangerous)
            else:
                return False
                
        elif name in ["sscanf"]:
            if expr.op == idaapi.cot_call:
                arg_size = expr.a.size()
                has_var_arg = False
                for i in range(2, arg_size):  
                    arg = expr.a[i]
                    if arg.op == idaapi.cot_var:
                        has_var_arg = True
                        break
                if not has_var_arg:
                    return False 
                
                input_arg = expr.a[0]
                if input_arg.op == idaapi.cot_cast:
                    is_const = op_constant(input_arg.x.op, input_arg.x)
                else:
                    is_const = op_constant(input_arg.op, input_arg)
                    
                if is_const:
                    return False  # Filter out (constant input)
                else:
                    return True   # Keep this sink (dangerous)
            else:
                return False
                
        elif name in ["sprintf"]:
            if expr.op == idaapi.cot_call:
                dest_arg = expr.a[0]
                if dest_arg.op != idaapi.cot_var:    # dest is not a variable (Filter)
                    return False
                
                arg_size = expr.a.size()
                for i in range(2, arg_size):
                    arg_expr = expr.a[i]
                    if arg_expr.op == idaapi.cot_cast:
                        if not op_constant(arg_expr.x.op, arg_expr.x):
                            return True  # Keep this sink (dangerous)
                    else:
                        if not op_constant(arg_expr.op, arg_expr):
                            return True  # Keep this sink (dangerous)
                return False  # Filter out (all variable args are constants)
            else:
                return False
        else:
            print(f"  -> Unknown function {name}, keeping")
            return True
    except Exception as e:
        print(f"Error analyzing {hex(address)}: {e}")
        return True  

def get_full_statement_lines(cfunc, y):
    lines = cfunc.pseudocode
    total_lines = len(lines)
    collected = []
    bracket_count = 0
    started = False

    for i in range(y, total_lines):
        line = idaapi.tag_remove(lines[i].line)
        stripped = line.strip()

        if 'sprintf' in stripped or 'sscanf' in stripped:
            started = True

        collected.append(stripped)

        bracket_count += stripped.count('(')
        bracket_count -= stripped.count(')')

        if started and bracket_count <= 0:
            break  

    return ' '.join(collected)

def addr2pseudo(cfunc, addr):
    item = cfunc.body.find_closest_addr(addr)
 
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        print("Not found item line")
    y = y_holder.value()
    if y is not None and 0 <= y < len(cfunc.pseudocode):
        full_stmt = get_full_statement_lines(cfunc, y)
        print("Full statement:", full_stmt)
    return full_stmt

def FilterInteger(call_ea,libc_func):              
    result_flag=False
    function = idaapi.get_func(call_ea)
    cfunc = idaapi.decompile(function)
    code = addr2pseudo(cfunc, call_ea)
    if libc_func=='sscanf':
        format_strings = re.findall(r'sscanf\s*\(\s*[^,]+,\s*"((?:[^"\\]|\\.)*)"', code)
    else:
        format_strings = re.findall(r'sprintf\s*\(\s*[^,]+,\s*"((?:[^"\\]|\\.)*)"', code)
    for format_string in format_strings:
        if '%s' in format_string:
            result_flag=True
            return result_flag
        else:
            continue
    return result_flag

class StrcpyVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, ea, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.ea = ea
        self.cfunc = cfunc
        self.src_varname = None
        self.dst_varname = None

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call:
            func_ea = expr.x.obj_ea
            func_name = idaapi.get_func_name(func_ea)
            
            if func_name == "strcpy":
                if len(expr.a) == 2:
                    dst_expr = expr.a[0]  
                    src_expr = expr.a[1]  
                    
                    if dst_expr.op == ida_hexrays.cot_var:
                        self.dst_varname = self.cfunc.lvars[dst_expr.v.idx].name
                    
                    if src_expr.op == ida_hexrays.cot_var:
                        self.src_varname = self.cfunc.lvars[src_expr.v.idx].name
                    return 1  
        return 0

def get_strcpy_varnames(ea):  
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        print("Decompilation failed")
        return None, None

    visitor = StrcpyVisitor(ea, cfunc)
    visitor.apply_to(cfunc.body, None)

    return visitor.dst_varname, visitor.src_varname

def FilterSize(refs_addr,Dangerous_function):  
    if Dangerous_function not in type_3_list:
        return True
    func_code=str(ida_hexrays.decompile(refs_addr))
    src_def_length=0
    dst_def_length=0
    arg_dst, arg_src=get_strcpy_varnames(refs_addr)
    if arg_src:   
        func_code_list=func_code.split('\n')
        number=func_code_list.index('')
        
        src_def_length=stack_variable_defination(func_code_list,number,arg_src)
        
        if 0 < src_def_length < 20:      
            return False
        else:
            if arg_dst:   
                dst_def_length=stack_variable_defination(func_code_list,number,arg_dst)
                if src_def_length>0 and dst_def_length>0 and src_def_length <= dst_def_length:
                    return False       
                else:
                    return True
            else:
                return True
    else:
        result=variable_filter(arg_src) 
        return result 
    
def is_dangerous(call_ea, Dangerous_function):
    if Dangerous_function in ['strcpy','memcpy','system','popen', "CsteSystem", '_system', "doSystemCmd", "twsystem", "doSystem"]:
        type1_result = FilterConstant(call_ea)
        type3_result = FilterSize(call_ea, Dangerous_function)
        if type1_result and type3_result:   
            return True
    elif Dangerous_function in ['sscanf', 'sprintf']:
        type1_result = FilterConstant(call_ea)
        type2_result = FilterInteger(call_ea, Dangerous_function)
        if type1_result and type2_result:      
            return True         

def Analysis_main(Dangerous_function):
    addr=ida_name.get_name_ea(ida_idaapi.BADADDR, Dangerous_function)
    refs=list(idautils.CodeRefsTo(addr,0))  
    
    dangerous_sinks = []  # Store dangerous sink points
    safe_sinks = []      # Store filtered out safe sink points
    
    for i in range(0,len(refs)):
        try:
            call_ea=refs[i]         
            if is_dangerous(call_ea, Dangerous_function):
                dangerous_sinks.append(hex(refs[i]))
                print(f'  -> DANGEROUS SINK: {hex(refs[i])}')
            else:
                safe_sinks.append(hex(refs[i]))
                print(f'  -> Filtered out: {hex(refs[i])}')
                
        except Exception as e:
            print(f'Error processing {hex(refs[i])}: {e}')
            continue
    
    return dangerous_sinks, safe_sinks

def output_results(results):
    """Output filtered sink points to files"""
    with open('sink_analysis_summary.txt', 'w') as file:
        file.write("=== SINK POINT FILTERING RESULTS ===\n\n")
        
        total_dangerous = 0
        total_safe = 0
        
        for func_name, (dangerous, safe) in results.items():
            file.write(f"{func_name}:\n")
            file.write(f"  Total references: {len(dangerous) + len(safe)}\n")
            file.write(f"  Dangerous sinks: {len(dangerous)}\n")
            file.write(f"  Filtered out: {len(safe)}\n")
            
            if len(safe) > 0:
                file.write("  Safe addresses:\n")
                for addr in safe:
                    file.write(f"    {addr}\n")
            
            if len(dangerous) > 0:
                file.write("  Dangerous addresses:\n")
                for addr in dangerous:
                    file.write(f"    {addr}\n")
            
            filter_rate = len(safe) / (len(dangerous) + len(safe)) * 100 if (len(dangerous) + len(safe)) > 0 else 0
            file.write(f"  Filter rate: {filter_rate:.2f}%\n\n")
            
            total_dangerous += len(dangerous)
            total_safe += len(safe)
        
        file.write("=== OVERALL SUMMARY ===\n")
        file.write(f"Total sink points found: {total_dangerous + total_safe}\n")
        file.write(f"Dangerous sinks: {total_dangerous}\n") 
        file.write(f"Safe sinks: {total_safe}\n")
        
        overall_filter_rate = total_safe / (total_dangerous + total_safe) * 100 if (total_dangerous + total_safe) > 0 else 0
        file.write(f"Overall filter rate: {overall_filter_rate:.2f}%\n")
        print(f"=== OVERALL SUMMARY ===\nTotal sink points found: {total_dangerous + total_safe}\nDangerous sinks: {total_dangerous}\nSafe sinks: {total_safe}Overall filter rate: {overall_filter_rate:.2f}%\n")
        

if __name__ == '__main__':
    print("Starting sink point analysis...")
    
    results = {}
    
    for sink_func in sink_function:    
        print(f"\n{'='*50}")
        print(f"Analyzing sink function: {sink_func}")
        print('='*50)
        
        dangerous_sinks, safe_sinks = Analysis_main(sink_func)
        if dangerous_sinks != [] and safe_sinks != []:
            results[sink_func] = (dangerous_sinks, safe_sinks)
        
    # Output all results
    output_results(results)
    
    print("\nSink point filtering analysis completed!")