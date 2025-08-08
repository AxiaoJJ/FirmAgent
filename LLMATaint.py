#coding=gbk
import argparse
import logging
import os
import pickle
import sys
import angr
import sys
import TaintChecker
import Taintanalysis
from collections import Counter
import time
import subprocess
import datetime

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('angr.analyses').setLevel('ERROR')
logging.getLogger('claripy').setLevel('ERROR')
logging.getLogger('cle').setLevel('ERROR')

class ida_function_info():
    def __init__(self, func_addr = None, func_name = None, is_source_func= False):
        self.func_addr = func_addr
        self.func_name = func_name
        self.is_source_func = is_source_func

def argsparse():
    # Parse command line parameters
    parser = argparse.ArgumentParser(description="LLManalysis",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-b", "--bin", required=True, metavar="/var/ac18/bin/httpd",
                       help="Input border bin")

    parser.add_argument("-p", "--preload", required=False, metavar="/True/False", help="Enable preload angr project and angr CFG")

    parser.add_argument("-t", "--type", required=True, metavar="bof/ci/fmt/csrf/cgixss/sqltaint/useofhttp/taintpath/"
                                                               "exposesystemdata/predictseed",
                       help="Taint check type")

    parser.add_argument("-o", "--output", required=True, metavar="/root/output",
                        help="Folder for output results")

    parser.add_argument("-m", "--model", required=True, metavar="deepseek",
                        help="LLM model")
    
    parser.add_argument("-e", "--extract", required=False, action="store_true",
                        help="static extract")

    args = parser.parse_args()

    if not os.path.exists(args.bin):
        logging.error("Target bin: {} not found".format(args.bin))
        sys.exit()

    taint_type = ['bof', "ci", "fmt", "useofhttp", "csrf", "sqltaint", "predictseed", "taintpath", "cgixss"]
    if args.type not in taint_type:
        logging.error("Taint strategy: {} not found".format(args.bin))
        sys.exit()

    if args.preload:
        if args.preload == "True" or args.preload == "False":
            logging.info("Valid preload.")
        else:
            logging.error("Invalid preload value {}".format(args.preload))
            sys.exit()

    if not os.path.exists(args.output):
        logging.warning("Output dictionary: {}  not found".format(args.output))
        logging.warning("Making output dictionary by default")
        os.makedirs(args.output)

    return args


def ida_filter_sink(sinks_info, vuls_scanner, args, bin_dir):
    sink_addr = []
    base_addr = vuls_scanner.bin_project.loader.main_object.mapped_base            
    for sink_info in sinks_info:
        if 'mips' in vuls_scanner.arch.name.lower():
            sink_addr.append(sink_info[1].instruction_addrs[-2])
        else:
            sink_addr.append(sink_info[1].instruction_addrs[-1])            
    sink_addr_str = ' '.join(map(hex,sink_addr))
    if not os.path.exists(f"{bin_dir}/filter_sink_{args.type}.txt"):
        with open(f"{bin_dir}/all_sink_addr_{args.type}.txt", 'w') as file:
            file.write(sink_addr_str)
        if os.path.exists(f'{args.bin}.i64'):
            subprocess.run(['idat', "-A", "-Lida.log", f"-SFilter/FilterSink.py {base_addr} {args.type}", f'{args.bin}.i64'], check=True)
        else:
            subprocess.run(['idat', "-A", "-Lida.log", f"-SFilter/FilterSink.py {base_addr} {args.type}", args.bin], check=True)
    with open(f"{bin_dir}/filter_sink_{args.type}.txt", "r") as file:
        filter_sinks_addr = file.read().split()
    if 'mips' in vuls_scanner.arch.name.lower():
        filter_sinks_info = [x for x in sinks_info if (hex(x[1].instruction_addrs[-2]) in filter_sinks_addr)]
    else:
        filter_sinks_info = [x for x in sinks_info if (hex(x[1].instruction_addrs[-1]) in filter_sinks_addr)]
    return filter_sinks_info    
 
def str_to_bool(str):
    return True if str.lower() == 'true' else False

def print_info(sources_info, sinks_info):
    source_point_name = [x[2] for x in sources_info]
    source_point_counter = Counter(source_point_name)
    print("source_function_name and occurrences:")
    for name, count in source_point_counter.items():
        print(f"  {name}: {count}")
    
    sink_point_name = [x[2] for x in sinks_info]
    sink_point_counter = Counter(sink_point_name)
    print("sink_function_name and occurrences:")
    for name, count in sink_point_counter.items():
        print(f"  {name}: {count}")

def main():
    logging.info("Start Analysis:")
    start_time = time.time()
    args = argsparse()
    ida_function_addrs = []
    functions_info = []
    script = args.bin + '_functions_info.txt'
    ori_script = args.bin + '_functions_info_bak.txt'
    origin_str = args.bin + '_origin_strs.txt'
    bin_dir = os.path.dirname(args.bin)
    if not os.path.exists(script) and os.path.exists(origin_str):
        subprocess.run(['idat', "-A", "-Lida.log", "-SRestruct_Enhanced_CFG.py", f'{args.bin}'], check=True, cwd=os.getcwd())
        return
    
    if not os.path.exists(f'{args.bin}.i64'):
        subprocess.run(['idat', "-A", "-Lida.log", "-SCreateFunc.py", f'{args.bin}'], check=True, cwd=os.getcwd())
    
        
    if os.path.exists(script):
        with open(script, 'r') as function_list:
            lines = function_list.readlines()
            for line in lines:
                func_addr = line.split(' name: ')[0]
                func_name = line.split(' name: ')[1].split(' seg:')[0]
                source_func = line.split(' name: ')[1].split(' seg:')[1].split(' source_function: ')[1].strip('\n')
                is_source_func = str_to_bool(source_func)
                functions_info.append(ida_function_info(func_addr=func_addr, func_name=func_name, is_source_func=is_source_func))

        for function_info in functions_info:
            ida_function_addrs.append(int(function_info.func_addr))

    if args.type and args.bin:
        taint_engine = TaintChecker.TaintEngine(vul_type=args.type)
        taint_engine.set_source_sink()

        for function_info in functions_info:
            if function_info.is_source_func == True and function_info.func_name not in taint_engine.sources_name_list:
                taint_engine.add_source_functions(function_info.func_name)

        taint_engine.update_function_summary()

        if args.preload=="False":
            vuls_scanner = Taintanalysis.LLManalysis(bin_name=args.bin,
                                                  vul_type=taint_engine.vul_type,
                                                  ida_function_addresses=ida_function_addrs)
        else:
            cfg_name = args.bin + "_cfg"
            project_name = args.bin + "_angr"
            bin_cfg = pickle.load(open(cfg_name, "rb"))
            project = angr.Project._load(project_name)

            vuls_scanner = Taintanalysis.LLManalysis(bin_name=args.bin,
                                                  vul_type=taint_engine.vul_type,
                                                  ida_function_addresses=ida_function_addrs,
                                                  project=project,
                                                  cfg=bin_cfg)
        if not args.extract:
            sink_addrs = []
            source_addrs = []

            sink_name_list = getattr(taint_engine, args.type + '_name_list')
            vuls_scanner.recover_symbol(functions_info)
            vuls_scanner.recover_plt(functions_info)
            vuls_scanner.bin_project.kb.functions = vuls_scanner.bin_cfg.kb.functions   
            vuls_scanner.lib_scan(sink_addrs, source_addrs, sink_name_list, taint_engine.sources_name_list)
            sinks_info = vuls_scanner.get_sinks_node(sink_addrs)
            filter_sources_info = vuls_scanner.get_sources_node(taint_engine.sources_name_list, source_addrs)
            filter_sinks_info = ida_filter_sink(sinks_info, vuls_scanner, args, bin_dir)
            print_info(filter_sources_info, filter_sinks_info)
            vuls_scanner.bin_dir = os.path.dirname(args.bin)
        
            if not os.path.exists(f'{bin_dir}/potential_paths_{args.type}.pkl'):           
                callchains_len = vuls_scanner.get_potential_paths(args, filter_sinks_info, filter_sources_info)
            else:
                vuls_scanner.potential_paths = pickle.load(open(f'{bin_dir}/potential_paths_{args.type}.pkl','rb'))  
                
            if not os.path.exists(f'{bin_dir}/code_{args.type}.json'):                      
                if os.path.exists(f'{args.bin}.i64'):
                    subprocess.run(['idat', "-A", "-Lida.log", f"-SGetPseudocode.py {args.type}", f'{args.bin}.i64'], check=True)
                else:
                    subprocess.run(['idat', "-A", "-Lida.log", f"-SGetPseudocode.py {args.type}", args.bin], check=True)

            #vuls_scanner.LLM_analysis_FourRole(args.output, args.type, args.model)
            vuls_scanner.LLM_analysis(args.output, args.type, args.model, args.bin)
            end_time = time.time()
            print(f"Analysis time is {int((end_time - start_time)/60)}")
            with open(f"{args.output}/vuln_{os.path.basename(bin_dir)}_{args.type}_{args.model}.md",'a') as vuln_file:
                vuln_file.write(f"The potential_paths length is {len(vuls_scanner.potential_paths)}\nAnalysis time is {int((end_time - start_time)/60)}m")           

if __name__ == "__main__":
    main()