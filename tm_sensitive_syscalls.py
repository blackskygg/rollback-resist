from joern.all import JoernSteps


#the format of the elements is (name, [affected parameters])
#and we see the return value as the 0th parameter
sys_calls = {
    #below are time-sensitive sys-calls in linux
    #See https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
    #for a full reference to x86_64 Linux system calls
    "gettimeofday": [1], 
    "sysinfo": [1], #including system uptime
    "times": [0, 1], #usr/sys time etc
    "adjtimex": [1],
    "ntp_adjtime": [1],
    "time": [0, 1],
    "timer_gettime": [2],
    "timer_getoverrun": [0],
    "clock_gettime": [2],
    "timerfd_gettime": [2],
    "getrandom": [1],
    
    #below are from C standard lib, based on the C11 standard
    "clock": [0],
    "rand": [0]}


def node2id(node):
    return int(node.ref[5:])

"""
find out all "&" operator in an expression and extract the operand
@param[in]    node_id    expression node id
@return                  a list of (code, functionID) of variables who are operandsof
                         the "&" operator
"""
def get_param_vars(node_id):
    result = []
    
    node = j.runGremlinQuery("g.v(%d)"%(node_id))
    if node['type'] == 'UnaryOp' and node.properties['code'][0] == '&':
        ident_list = j.runGremlinQuery("g.v(%d).outE('IS_AST_PARENT')"
                                       ".inV().filter{it.type == 'Identifier'}"%(node_id))
        for ident_node in ident_list:
            result.append((ident_node.properties['code'], ident_node.properties['functionId']))
    else:
        for id in j.runGremlinQuery("g.v(%d).outE('IS_AST_PARENT').inV().id"%(node_id)):
            result.extend(get_param_vars(id));
        
    return result


"""
given a list of (code, functionId), return the corresponding symbol node IDs.
@param[in]    ident_list    list of (code, functionID)
@return                     list of symbol IDs
"""    
def code_to_symbols(ident_list):
    sym_list = []
    for code, funcid in ident_list:
        try:
            id = node2id(j.runGremlinQuery("g.V().filter{it.type == 'Symbol' "
                                           "&&it.functionId == %d && it.code == '%s'}" \
                                           %(funcid, code))[0])
            sym_list.append(id)
        except IndexError:
            pass

    return sym_list


"""
given a statment containing funcion calls, find out the return value
@parm[in]    node_id    the ID of the expression/statement to be examined
@return                 (code, functionID) of the return value
"""
def find_retval(node_id):
    #some times node_id is a single-element list
    if isinstance(node_id, list):
        node_id = node_id[0]

    node_type = j.runGremlinQuery("g.v(%d)"%(node_id))['type']
    if 'ExpressionStatement' ==  node_type:
        return None
    elif 'AssignmentExpr' == node_type:
        node =  j.runGremlinQuery("g.v(%d)"
                                  ".outE('IS_AST_PARENT')"
                                  ".inV()"%(node_id))[0]
        return (node.properties['code'], node.properties['functionId'])
    else:
        return find_retval(j.runGremlinQuery("g.v(%d)"
                                            ".inE('IS_AST_PARENT')"
                                            ".outV().id"%(node_id)))

"""
given a list of IDs of symbol nodes, return a list of condition statments
"""
def get_ifs(sym_list):
    result = []
    for sym in sym_list:
        result.extend(j.runGremlinQuery("g.v(%d).inE('USE')"
                                        ".outV()"
                                        ".filter{it.type == 'Condition'}"%(sym)))
    return result

def process_call(call_id):
    affected_vars = set()
    ast_children = j.runGremlinQuery("g.v(%d)"
                                ".outE('IS_AST_PARENT')"
                                ".inV()"%(call_id))

    callee = ast_children[0].properties['code']
    
    tm_params = sys_calls.get(callee, None)
    if not tm_params:
        return
    
    #process it's actual param list
    if len(ast_children) == 2:
        actual_params = j.runGremlinQuery("g.v(%d)"
                                          "outE('IS_AST_PARENT')"
                                          ".inV()"%(node2id(ast_children[1])))
        
    #calculate the affected variables                                      
    for param in tm_params:
        if param == 0:
            retval = find_retval(call_id)
            if retval: affected_vars.add(retval)
        else:
            vars = get_param_vars(node2id(actual_params[param-1]))
            for v in vars:
                affected_vars.add(v)

    print get_ifs(code_to_symbols(affected_vars));

    
j = JoernSteps()
j.setGraphDbURL('http://localhost:7474/db/data/')
j.connectToDatabase()

#find out all call expressions and process them one by one
call_ids = j.runGremlinQuery("g.V().filter{it.type == 'CallExpression'}.id()")
for call_id in call_ids:
    process_call(call_id)
