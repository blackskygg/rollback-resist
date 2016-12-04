from joern.all import JoernSteps
import Queue

def bfs(src, dsts):
    """ 
    src: int
    dsts: list[int]
    returns true if there's not any path from dsts to src 
    """

    visited = set([src])
    q = Queue.Queue([src])

    flag = False
    while not q.empty():
        s = q.get()
        for next_id in j.runGremlinQuery("g.v(%d).inE('FLOWS_TO').outV().id()"%(s)):
            if next_id in dsts:
                return True
            
            if next_id not in visited:
                visited.add(next_id)
                q.put(next_id)

    return False
        

def process_defs(var_id, defs):
    """
    var_id: int, the variable's id to be examined
    defs: list[int], list of nodes who've changed the var's value
    returns true if var_id is time-sensitive
    """
    dsts = set()
    srcs = set()
    for id in defs:
        uses = j.runGremlinQuery("g.v(%d).uses().id()"%id)
        if var_id in uses:
            dsts.add(id)
        else:
            srcs.add(id)

    if not dsts:
        return False
        
    for src in srcs:
        if bfs(src, dsts):
            return False

    return True

j = JoernSteps()
j.setGraphDbURL('http://localhost:7474/db/data/')
j.connectToDatabase()

variables = j.runGremlinQuery("g.V()"
                              ".filter{it.type == 'IdentifierDeclStatement'}"
                              ".defines().id()")
result = []

for v in variables:
    defs = j.runGremlinQuery("g.v(%d).inE('DEF')"
                             ".outV().filter{it.isCFGNode == 'True'}.id()"%(v))
    if process_defs(v, defs):
        print v
        result.extend(j.runGremlinQuery("g.v(%d).inE('USE')"
                                        ".outV()"
                                        ".filter{it.type == 'Condition'}"%(v)))

print result
