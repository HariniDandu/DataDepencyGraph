from idaapi import *
from idautils import *
from idc import *
import ida_allins
import ida_ua
import idaapi
import json
import re
import ida_nalt
import graphviz
# import CFG


class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is CFG Plugin"
    wanted_name = "Harini Python plugin"
    wanted_hotkey = "Ctrl-A"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("------CFG Plugin Running-----")
        CFGmain()
        print("------CFG Plugin End-----")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()


basepath0 = "./assignment4/allFiles/"

FunctionsFile = basepath0 + "FunctionsFile/"
InstructionsFile = basepath0 + "InstructionsFile/"
basepath = basepath0 + "alldots/"
basepathDDG = basepath0 + "DDG/"
testpath = basepath0 + "test/"

unique_instructions = {}
list_of_unique_functions = set()
allFunctions = {} #{functionName: counter} (counter: no. of times it  has come across?)

def writeToFile(output_filename, text):
    output_file = open(output_filename,'a') # 'a' creates a file if it doesn't exist and appends to the file (does not truncate, unlike w) if it exists
    output_file.write(text+"\n")
    return

def CFGmain():
    for seg in Segments():
        seg_start_addr = idc.get_segm_start(seg)
        seg_end_addr = idc.get_segm_end(seg)
        for funcea in Functions(seg_start_addr, seg_end_addr):
            functionName = get_func_name(funcea)
            list_of_unique_functions.add(functionName)
            handleCurrentFunction(funcea, functionName)          
    # for i in unique_instructions:
    #     writeToFile(InstructionsFile+"uniqueInstructions", str(i) + " " + str(unique_instructions[i])+ "\n")

def handleCurrentFunction(funcea, functionName):
    cfg = []
    #cfg1 = []
    node_addr = {}  
    cfg2 = {}
    node_addr_ddg = {}
    if functionName in allFunctions:
        counter = allFunctions[functionName] + 1
    else:
        allFunctions[functionName] = 1
        counter = 1
    for (startea, endea) in Chunks(funcea):
        for head in Heads(startea, endea):
            addr = "%08x"%(head)
            if addr not in node_addr:
                node_addr[addr] = ["n"+str(counter),[],[], addr]
                node_addr_ddg[addr] = ["n"+str(counter),[],[],[]]
                counter += 1
    for (startea, endea) in Chunks(funcea):
        for head in Heads(startea, endea):
            addr = "%08x"%(head)
            next_addr = "%08x"%(next_head(head,find_func_end(get_func(funcea).start_ea)))
            instruction = idaapi.insn_t()
            length = decode_insn(instruction, head)
            if isBranch(funcea, head) == 1: #unconditional branch
                getDUofAnInstruction('Conditional', head, counter, functionName, node_addr)
                getUniqueInstructions(instruction, functionName, addr, head, node_addr)
                hexBranchAddr = "%08x"%(instruction.ops[0].addr)
                cfg.append(node_addr[addr][0] + " -> " + node_addr[next_addr][0])
                cfg.append(node_addr[addr][0] + " -> " + node_addr[hexBranchAddr][0])
                #cfg1.append([node_addr[addr], node_addr[next_addr]])
                #cfg1.append([node_addr[addr], node_addr[hexBranchAddr]])
                node_key = node_addr[addr][0]
                if node_key not in cfg2:
                    cfg2[node_key] = []
                cfg2[node_key].append(node_addr[next_addr][0])
                cfg2[node_key].append(node_addr[hexBranchAddr][0])
            elif isBranch(funcea, head) == 2:   #conditional branch
                results = isSwitch(head)
                if bool(results) == 0:
                    getDUofAnInstruction('Unconditional', head, counter, functionName, node_addr)
                    getUniqueInstructions(instruction, functionName, addr, head, node_addr)
                    hexBranchAddr = "%08x"%(instruction.ops[0].addr)
                    cfg.append(node_addr[addr][0] + " -> " + node_addr[hexBranchAddr][0])
                    #cfg1.append([node_addr[addr], node_addr[hexBranchAddr]])
                    node_key = node_addr[addr][0]
                    if node_key not in cfg2:
                        cfg2[node_key] = []
                    cfg2[node_key].append(node_addr[hexBranchAddr][0])
                else:
                    node_addr[addr][1].append('')
                    node_addr[addr][2].append('ds:jpt_401724[edi*4],edi')
                    for idx in range(len(results.cases)):
                        getUniqueInstructions(instruction, functionName, addr, head, node_addr)
                        hexBranchAddr = "%08x"%(results.targets[idx])
                        cfg.append(node_addr[addr][0] + " -> " + node_addr[hexBranchAddr][0])
                        #cfg1.append([node_addr[addr], node_addr[hexBranchAddr]])
                        node_key = node_addr[addr][0]
                        if node_key not in cfg2:
                            cfg2[node_key] = []
                        cfg2[node_key].append(node_addr[hexBranchAddr][0])            
            else:   #no branch
                getDUofAnInstruction('', head, counter, functionName, node_addr)
                getUniqueInstructions(instruction, functionName, addr, head, node_addr)
                if head != endea and next_addr != 'ffffffff':
                    cfg.append(node_addr[addr][0] + " -> " + node_addr[next_addr][0] + "")
                    #cfg1.append([node_addr[addr], node_addr[next_addr]])     #WHY ""?  
                    node_key = node_addr[addr][0]  
                    if node_key not in cfg2:
                        cfg2[node_key] = []
                    cfg2[node_key].append(node_addr[next_addr][0])
                    if node_addr[next_addr][0] not in cfg2:
                        cfg2[node_addr[next_addr][0]] = []

    #f = open(basepath+functionName+".dot", 'a')
    #f1 = open(testpath+functionName+"XOXO.dot", 'a')
    #f2 = open(testpath+functionName+"DDG.dot", 'a#'
    #f3 = open(testpath+functionName+"DG.dot", 'a')
    #f.write("digraph G { \n")
    for addr in node_addr:
        #f.write(str(node_addr[addr][0])+ " [label=\""+ str(addr) + "; D:" + formatDU(node_addr[addr][1]) + ", U:"+ formatDU(node_addr[addr][2])+ "\"]\n")
        #f1.write(str(node_addr[addr][1])+'\n')
        #node_addr_ddg
        node_addr_ddg[addr][0] = node_addr[addr][0]
        node_addr_ddg[addr][1] = addr
        node_addr_ddg[addr][2] = formatDU(node_addr[addr][1]).split(',') #Def
        node_addr_ddg[addr][3] = formatDU(node_addr[addr][2]).split(',') #Use
        #f3.write(node_addr_ddg[addr][2]+"\n\n")
    node_num_each_func = []
    node_def = []
    node_use = []
    node_address = []
    for key in node_addr_ddg:
        node_num_each_func.append(str(node_addr_ddg[key][0]))
        node_address.append(node_addr_ddg[key][1])
        node_def.append(node_addr_ddg[key][2])
        node_use.append(node_addr_ddg[key][3])
    #f3 = open(testpath+functionName+"func_def.dot", 'a')
    #f4 = open(testpath+functionName+"func_use.dot", 'a')
    #f3.write(str(node_def))
    #f4.write(str(node_use))
    #f3.close()
    #f4.close()
    DFS_traversal_paths(functionName, node_num_each_func, cfg2, node_def, node_use, node_address, funcea) #for each function find DDG
    return

def getUniqueInstructions(instruction, functionName, addr, head, node_addr):
    if (instruction.itype, instruction.ops[0].type, instruction.ops[1].type) not in unique_instructions:
        unique_instructions[(instruction.itype, instruction.ops[0].type, instruction.ops[1].type)] = str(functionName)+ " " + str(addr) + " " + str(GetDisasm(head).split(';', 1))+ " -----> D:" + formatDU(node_addr[addr][1]) + ", U:"+ formatDU(node_addr[addr][2])
    return


def isSwitch(ea):
    si = idaapi.get_switch_info(ea)
    try:
        results = idaapi.calc_switch_cases(ea, si)
        return results
    except:
        return None

def formatDU(lst):
    res = ','.join(map(str, set(list(filter(('').__ne__, lst)))))
    return res

def isBranch(funcea, addr):

    startea = get_func(funcea).start_ea
    endea = find_func_end(startea)

    refs = CodeRefsFrom(addr, 0)
    refs = set(filter(lambda x: x>=startea and x<=endea, refs))
    if refs:
        next_head = idc.next_head(addr, endea)
        if idc.is_flow(idc.get_full_flags(next_head)):
            return 1
        else:
            #unconditional branch
            return 2
    else:
        return 0

def getDUofAnInstruction(branchtype, head, counter, functionName, node_addr):
    addr = "%08x"%(head)
    instruction = insn_t()
    length = decode_insn(instruction, head)

    if branchtype == "Conditional":
        node_addr[addr][1].append('')
        node_addr[addr][2].append("eflags")
        return
   
    elif branchtype == "Unconditional":
        if instruction.itype == NN_jmp:
            if instruction.ops[0].type == ida_ua.o_reg:
                node_addr[addr][1].append(getOperandString(head,instruction,0))
                node_addr[addr][2].append(getOperandString(head,instruction,1))
                return
        elif instruction.itype == NN_jmpni:
            if instruction.ops[0].type in [ida_ua.o_displ, ida_ua.o_phrase, ida_ua.o_mem]:
                node_addr[addr][2].append('ds:jpt_401724[edi*4],edi')

    else:
        if instruction.itype == ida_allins.NN_push:
            value = ''
            if instruction.ops[0].type == ida_ua.o_reg:
                value = str(GetDisasm(head).split(';', 1)[0].split()[1])
            elif instruction.ops[0].type == ida_ua.o_imm:
                value = ''
            elif instruction.ops[0].type in [ida_ua.o_displ, ida_ua.o_phrase]:
                value = str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]) + "," + getOperandString(head, instruction,0)
            elif instruction.ops[0].type in [ida_ua.o_mem]:
                value = getOperandString(head,instruction,0)
            
            node_addr[addr][1].append('[esp]')
            node_addr[addr][1].append('esp')
            node_addr[addr][2].append(value)
            node_addr[addr][2].append('esp')
            return

        elif instruction.itype == ida_allins.NN_pop:
            value = ''
            if instruction.ops[0].type == ida_ua.o_reg:
                value = str(GetDisasm(head).split(';', 1)[0].split()[1])
            elif instruction.ops[0].type == ida_ua.o_imm:
                value = ''
            elif instruction.ops[0].type in [ida_ua.o_displ, ida_ua.o_phrase]:
                value = str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]) + getOperandString(head, instruction,0)
            node_addr[addr][1].append(value)
            node_addr[addr][1].append('esp')
            node_addr[addr][2].append('[esp]')
            node_addr[addr][2].append('esp')
            return

        elif instruction.itype in [NN_leave, NN_leaved, NN_leaveq, NN_leavew]:
            node_addr[addr][1].append('esp')
            node_addr[addr][1].append('ebp')
            node_addr[addr][2].append('ebp')
            return

        elif instruction.itype in [NN_retn, NN_retf,NN_retfd, NN_retfq, NN_retfw, NN_retnd, NN_retnq, NN_retnw]:
            node_addr[addr][1].append('esp')
            node_addr[addr][1].append('eip')
            node_addr[addr][2].append('esp')
            return
       
        elif instruction.itype in [NN_setnz]:
            node_addr[addr][1].append(getOperandString(head,instruction,0))
            node_addr[addr][2].append('eflags')

        else:
            if instruction.itype in [NN_stos]:
                node_addr[addr][1].append('[es:di]')
                node_addr[addr][2].append('eax')
                return

            elif instruction.itype in [NN_mov, NN_movsx, NN_movzx]:
                if instruction.ops[0].type in [ida_ua.o_displ, ida_ua.o_phrase]:
                    node_addr[addr][1].append(str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]))
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
                elif instruction.ops[0].type in [o_mem]:
                    node_addr[addr][1].append(getOperandString(head,instruction,0))
                elif instruction.ops[0].type in [o_reg]:
                    node_addr[addr][1].append(getOperandString(head,instruction,0))

                if instruction.ops[1].type in [ida_ua.o_displ, ida_ua.o_phrase]:
                    node_addr[addr][2].append(GetDisasm(head).split(';', 1)[0].split()[-1])
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                elif instruction.ops[1].type in [ida_ua.o_reg]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                elif instruction.ops[1].type in [ida_ua.o_mem]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))

            elif instruction.itype in [NN_lea]:
                # if instruction.ops[1].type in [ida_ua.o_displ, ida_ua.o_mem]:
                node_addr[addr][1].append(getOperandString(head,instruction,0))
                node_addr[addr][2].append(getOperandString(head,instruction,1))
                return

            elif instruction.itype in [NN_add, NN_inc, NN_sub, NN_sar, NN_shr, NN_imul, NN_and, NN_or, NN_dec]:
                node_addr[addr][1].append('eflags')

                if instruction.ops[0].type in [ida_ua.o_phrase, ida_ua.o_displ]:
                    node_addr[addr][1].append(str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]))
                    node_addr[addr][2].append(str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]))
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
                elif instruction.ops[0].type in [ida_ua.o_reg]:
                    node_addr[addr][1].append(getOperandString(head,instruction,0))
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
                elif instruction.ops[0].type in [ida_ua.o_mem]:
                    node_addr[addr][1].append(getOperandString(head,instruction,0))
                    node_addr[addr][2].append(getOperandString(head,instruction,0))

                if instruction.ops[1].type in [ida_ua.o_phrase, ida_ua.o_displ]:
                    node_addr[addr][2].append(str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]))
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                elif instruction.ops[1].type in [ida_ua.o_reg]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                elif instruction.ops[1].type in [ida_ua.o_mem]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                   
                return
                   
            elif instruction.itype in [NN_xor]:
                node_addr[addr][1].append('eflags')
                node_addr[addr][1].append(getOperandString(head,instruction,0))
                node_addr[addr][2].append(getOperandString(head,instruction,1))
                return

            elif instruction.itype in [NN_cmp, NN_test]:
                node_addr[addr][1].append('eflags')
               
                if instruction.ops[0].type in [ida_ua.o_phrase, ida_ua.o_displ]:
                    node_addr[addr][2].append(str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]))
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
                elif instruction.ops[0].type in [ida_ua.o_reg]:
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
                elif instruction.ops[0].type in [ida_ua.o_mem]:
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
               
                if instruction.ops[1].type in [ida_ua.o_phrase, ida_ua.o_displ]:
                    node_addr[addr][2].append(str(re.findall('\[.*\]', GetDisasm(head).split(';', 1)[0])[0]))
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                elif instruction.ops[1].type in [ida_ua.o_reg]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                elif instruction.ops[1].type in [ida_ua.o_mem]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))

            elif instruction.itype in [NN_call,NN_callfi,NN_callni]:
                if instruction.ops[0].type in [ida_ua.o_reg]:
                    node_addr[addr][2].append(getOperandString(head,instruction,1))
                    node_addr[addr][1].append('eax')
                else:
                    node_addr[addr][1].append('eax')
                    node_addr[addr][1].append('esp')
                    node_addr[addr][2].append('esp')
                return

            elif instruction.itype == NN_jmpni:
                if instruction.ops[0].type in [ida_ua.o_displ, ida_ua.o_phrase, ida_ua.o_mem]:
                    node_addr[addr][2].append(getOperandString(head,instruction,0))
                    if 'edi' in getOperandString(head,instruction,0):
                        node_addr[addr][2].append('edi')

            else:
                node_addr[addr][1].append(getOperandString(head,instruction,0))
                node_addr[addr][2].append(getOperandString(head,instruction,1))
                return
    return


def getOperandString(head, instruction, opsNumber):
    Opd = ''
    if instruction.ops[opsNumber].type != ida_ua.o_void:
        if instruction.ops[opsNumber].type == ida_ua.o_reg:
            if opsNumber == 0:
                if instruction.ops[1].type != o_void:
                    Opd = GetDisasm(head).split(';', 1)[0].split()[1][:-1]
                else:
                    Opd = GetDisasm(head).split(';', 1)[0].split()[-1]
            else:
                Opd = GetDisasm(head).split(';', 1)[0].split()[-1]

        elif instruction.ops[opsNumber].type in [ida_ua.o_phrase, ida_ua.o_displ]:
           
            phraseString = re.findall('\[(.*)\]', GetDisasm(head).split(';', 1)[0])
            if len(phraseString) > 0:
                Opd = formatDU([i for i in re.split('\+|\-',phraseString[0]) if i[0] is 'e'])
            else:
                Opd = ''

        elif instruction.ops[opsNumber].type == ida_ua.o_imm:
            lstOps = GetDisasm(head).split(';', 1)[0].split()
            Opd = ''

        elif instruction.ops[opsNumber].type == ida_ua.o_mem:
            # lstOps = GetDisasm(head).split(';', 1)[0].split()
            # if opsNumber==0:
            #     if instruction.ops[1].type != o_void:
            #         Opd = GetDisasm(head).split(';', 1)[0].split()[1][:-1]
            #     else:
            #         Opd = GetDisasm(head).split(';', 1)[0].split()[-1]
            # else:
            #     Opd = GetDisasm(head).split(';', 1)[0].split()[-1]
            if instruction.ops[1].type != o_void:
                op1 = ' '.join(GetDisasm(head).split(';', 1)[0].split(';', 1)[0].split(',')[0].split()[1:])
                op2 = GetDisasm(head).split(';', 1)[0].split(';', 1)[0].split(',')[-1]
                op = GetDisasm(head).split(';', 1)[0].split(';', 1)[0].split(',')[0].split()[0]
                if opsNumber==0:
                    Opd = op1
                elif opsNumber==1:
                    Opd = op2
            else:
                op1 = ' '.join(GetDisasm(head).split(';', 1)[0].split(';', 1)[0].split(',')[0].split()[1:])
                op = GetDisasm(head).split(';', 1)[0].split(';', 1)[0].split(',')[0].split()[0]
                Opd = op1
    return Opd




#DDG description
#node_addr[addr] example: n1 [label="0040297d; D:esp,[esp], U:esp,ebp"]
#node_addr_ddg[0] = nx
#node_addr_ddg[1] = address of instr
#node_addr_ddg[2] = D
#node_addr_ddg[3] = U

def DFS_traversal_paths(functionName, Nodes, Edges, Def_list, Use_list, Addr_list, funcea):
    digraph = graphviz.Digraph(comment='{}'.format(functionName))
    digraph.node('n0',label='Start; DD: ')
    print("lalalal")
    ddg = {}
    # ddg['n0'] = ['Start', []]

    dict_mm = {}    # reg: address
    s=Nodes[0]  #"n1", "n2".....
    data_dep={} #nx: Dependenies
    shadow_stack = []
    visited = [2 for i in Nodes]    #iterate max 3 times for each node
    #visited = [False for i in Nodes]
    nodes_so_far = set()    #nodes traversed so far
    # Create a stack for DFS
    stack = []  #DFS stack
    # Push the current source node.
    stack.append((s, dict_mm, shadow_stack, nodes_so_far))
    while (len(stack)):
        # Pop a vertex from stack and print it
        (s, dict_mm, shadow_stack, nodes_so_far) = stack[-1]
        List_ans_final = []      #keeps track of DD for each node for each path
        print(functionName, s)
        stack.pop()     #pop from stack now that node has been traversed
        visited[Nodes.index(s)] = visited[Nodes.index(s)] - 1
       
        if((s not in nodes_so_far) and (visited[Nodes.index(s)]>=0)):
            nodes_so_far.add(s)
            #Find instruction type
            head = int(Addr_list[Nodes.index(s)],16)
            instruction = idaapi.insn_t()
            length = decode_insn(instruction, head)

            if (instruction.itype in [NN_call,NN_callfi,NN_callni]):
                List_ans = []
                List_args = get_arg_addrs(head)
                print("in call", List_args)
                if List_args:
                    for i in List_args:
                        List_ans_final.append("%08x"%(i))
                if instruction.itype in [NN_callni]:
                #     # print(s, "went in")
                    List_ans_final.append("Start")
                for Reg in Use_list[Nodes.index(s)]:
                    if Reg not in dict_mm:
                        List_ans.append("Start")
                    else:
                        List_ans.append(dict_mm[Reg])
                for Reg in Def_list[Nodes.index(s)]:    
                    dict_mm[Reg] = s
                
            else:
                List_ans = []
                if (instruction.itype == ida_allins.NN_push):   #Push
                    for Reg in Use_list[Nodes.index(s)]:
                        if Reg not in dict_mm:
                            List_ans.append("Start")
                        else:
                            List_ans.append(dict_mm[Reg]) #gives prev used node num of whatever reg is used in current instruction
                    for Reg in Def_list[Nodes.index(s)]:
                        # if not re.match("\[.*\]", Reg):
                        dict_mm[Reg] = s
                    shadow_stack.append(s)          
                elif (instruction.itype == ida_allins.NN_pop):  #pop
                    for Reg in Use_list[Nodes.index(s)]:
                        if (Reg == "esp"):
                            List_ans.append(dict_mm[Reg])
                    for Reg in Def_list[Nodes.index(s)]:
                        # if not re.match("\[.*\]", Reg):    
                        dict_mm[Reg] = s
                    if (shadow_stack != []):
                        List_ans.append(shadow_stack[-1])    #get top node value on the shadow stack for [rsp]
                        shadow_stack.pop()   #pop topmost value out of the stack
                else:

                    for Reg in Use_list[Nodes.index(s)]:
                        # if s == 'n40':
                        #     print('reg-use', Reg)
                        if Reg not in dict_mm:
                            if not re.match("\[e..\]s", Reg):
                                List_ans.append("Start")
                        else:
                            List_ans.append(dict_mm[Reg])
                    

                    for Reg in Def_list[Nodes.index(s)]:
                        if not re.match("\[e..\]", Reg):
                            dict_mm[Reg] = s
                    
                    if s == 'n57':
                        print("Use_list", Use_list[Nodes.index(s)], Def_list[Nodes.index(s)])
                        for i in dict_mm:
                            print(i, dict_mm[i])
                        print('\nList_ans-',List_ans)

            for n in List_ans:
                if n is "Start":
                    List_ans_final.append("Start")
                else:
                    List_ans_final.append(Addr_list[Nodes.index(n)])

            if List_ans_final:
                if(s not in data_dep):
                    data_dep[s]=set()
                for i in List_ans_final:
                    data_dep[s].add(i)
                if s not in ddg:
                    ddg[s] = ['',[]]
                ddg[s][0] = str(Addr_list[Nodes.index(s)])
                for x in data_dep[s]:
                    for y in x.split('s'):
                        ddg[s][1].append(y)
                
                # digraph.node(s,label=str(Addr_list[Nodes.index(s)])+ "; DD:"+",".join(str(x) for x in data_dep[s]))
            else:
                # digraph.node(s,label=str(Addr_list[Nodes.index(s)])+ "; DD:")
                if s not in ddg:
                    ddg[s] = ['',[]]
                ddg[s][0] = str(Addr_list[Nodes.index(s)])
            try:
                List_of_adj_nodes=Edges[s]
                for nx in List_of_adj_nodes:
                    copy_dict = dict_mm.copy()
                    if (nx not in nodes_so_far) and visited[Nodes.index(nx)]>=0:
                        stack.append((nx, copy_dict, shadow_stack, nodes_so_far.copy()))
   
            except Exception as e:
                print(e)
                print(Edges,functionName)
    for s in ddg:
        # if s == 'n36':
        #     print(ddg[s][1], formatDU(ddg[s][1]))
        digraph.node(s, label=ddg[s][0]+ "; DD:"+ formatDU(ddg[s][1]))
        #  + "----->"+GetDisasm(int(Addr_list[Nodes.index(s)],16)).split(';', 1)[0]

    for i in data_dep:
        for j in data_dep[i]:
            if j == 'Start':
                digraph.edge(i,'n0')
            else:
                digraph.edge(i, Nodes[Addr_list.index(j)])
    digraph.render(basepath0+basepath+"{}.dot".format(funcea))


#def Depth_first_search(cfg1, Search_var, node_addr_ddg):
#------------------IGNORE BELOW FUNCTIONS-------------------------------------------------------

def printAllPaths_rec(s, e, visited, path, U, functionName):
    # Mark the current node as visited and store in path
    visited[Nodes.index(s)]= True
    path.append(s)
    # If current vertex is same as destination, then print
    # current path[]
    if s == e:
        writeToFile(testpath+functionName+"Test_DDG.dot", str(path)+"\n")

    else:
        List_of_adj_nodes = []
        # If current vertex is not destination
        # Recur for all the vertices adjacent to this vertex
        for every_edge in Edges:
            if(every_edge[0]==s):
                List_of_adj_nodes.append(every_edge[1])
        for i in List_of_adj_nodes:
            if visited[Nodes.index(i)]== False:
                printAllPaths_rec(i, e, visited, path)
                 
    # Remove current vertex from path[] and mark it as unvisited
    path.pop()
    visited[Nodes.index(s)]= False
 
 
# Prints all paths from 's' to 'd'
def printAllPaths(s, e, Nodes, Edges, U, functionName):

    # Mark all the vertices as not visited
    visited = [False for i in Nodes]

    # Create an array to store paths
    path = []

    # Call the recursive helper function to print all paths
    printAllPaths_rec(s, e, visited, path, functionName)