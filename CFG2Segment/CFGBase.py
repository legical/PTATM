import angr

# Save flow related information for basic block.
class CFGNode:
    # 用给定的参数创建并返回一个新的CFGNode对象
    @staticmethod
    def init(name, block, block_id, has_return, is_syscall, function_address):
        node = CFGNode()
        # Basic block name.     表示基本块的名称。
        node.name = name
        # Basic block detail.   表示基本块的详细信息。
        node.block = block
        # Basic block id.       表示基本块的ID。
        node.block_id = block_id
        # Basic block address.  表示基本块的地址。
        node.addr = node.block.addr
        # Basic block size.     表示基本块的大小。
        node.size = node.block.size
        # Basic block is a system call? 表示基本块是否为系统调用。
        node.is_syscall = is_syscall
        # Basic block has return?       表示基本块是否具有返回操作
        node.has_return = has_return
        # Function address.             表示包含该基本块的函数的地址
        node.function_address = function_address
        # Predecessor CFG nodes.        一个列表，表示所有前驱节点的集合
        node.predecessors = list()
        # Successor CFG nodes.          一个列表，表示所有后继节点的集合
        node.successors = list()
        return node

    # 使用给定的angr.knowledge_plugins.cfg.cfg_node.CFGNode对象创建并返回一个新的CFGNode对象
    @staticmethod
    def fromAngrCFGNode(angr_node: angr.knowledge_plugins.cfg.cfg_node.CFGNode):
        node = CFGNode()
        node.name = angr_node.name
        node.block = angr_node.block
        node.block_id = angr_node.block_id
        node.addr = angr_node.addr
        node.size = angr_node.size
        node.is_syscall = angr_node.is_syscall
        node.has_return = angr_node.has_return
        node.function_address = angr_node.function_address
        node.predecessors = list()
        node.successors = list()
        return node

    # 从自身复制出一个新对象
    def copy(self):
        node = CFGNode()
        node.name = self.name
        node.block = self.block.copy()
        node.block_id = self.block_id
        node.addr = node.block.addr
        node.size = node.block.size
        node.is_syscall = self.is_syscall
        node.has_return = self.has_return
        node.function_address = self.function_address
        # Do not copy the neighborhoods, left it to CFG copy.
        node.predecessors = list()
        node.successors = list()
        return node

    # Modifier
    def appendSuccessor(self, node):
        if node not in self.successors:
            self.successors.append(node)
            node.predecessors.append(self)
            return self
        return None

    # remove predecessors?
    def removeSuccessor(self, node):
        # Raise exception anyway.
        self.predecessors.remove(node)
        node.successors.remove(self)

# Save function related information.
class Function:
    # [Attribute]
    #   addr                  函数地址        Function address.
    #   size                  函数大小        Function size.
    #   name                  函数名称        Function name.
    #   binary_name           函数所属的二进制文件的名称        Binary name of this function.
    #   angr_function                        Original angr function object.
    #   node_addrs_set        一个集合，表示所有CFG节点的地址   A set of all CFG nodes' address.
    #   nodes                                A dict which maps all addr to corresponding CFG node within this function.
    #   startpoint                           Entry CFG node of this function.
    #   endpoints                            A set of CFG nodes which can leave this function.
    #   endpoints_with_type                  A dict maps ending type to endpoints.
    #   has_return                           Whether this function has return.
    #   has_unresolved_calls                 Whether this function has unresolved calls.
    #   has_unresolved_jumps                 Whether this function has unresolved jumps.
    #   is_plt                               Whether this function is a plt function.
    #   is_syscall                           Whether this function is a syscall.
    #   is_simprocedure                      Whether this function is a simprocedure. (is_simprocedure? Maybe a hook function that doesn't exist?)
    #   is_default_name                      Whether the function name is a default name(default name cannot be used to probe directly).
    #   offset                               Function offset.
    #   callees                              A set of function address that may be called by this function.
    #   is_recursive                         Whether this function is a recursive function.
    # [Member]                
    #   get_node                             Get CFG node by addr.

    @staticmethod
    def fromAngrFunction(angr_function: angr.knowledge_plugins.functions.function.Function, angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast):
        # Normalize this function first if not normalized.
        if not angr_function.normalized:
            angr_function.normalize()
        # Normalize this cfg first if not normalized.
        if not angr_cfg.normalized:
            angr_cfg.normalize()

        # Build function object.
        func = Function()
        func.addr = angr_function.addr
        func.size = angr_function.size
        func.name = angr_function.name
        func.binary_name = angr_function.binary_name
        # func.angr_cfg = angr_cfg
        func.angr_function = angr_function
        func.node_addrs_set = angr_function.block_addrs_set.copy()
        # 一个字典，将每个地址映射到对应的CFG节点对象上
        func.nodes = {addr:CFGNode.fromAngrCFGNode(angr_cfg.model.get_any_node(addr)) for addr in func.node_addrs_set}
        func.startpoint = func.getNode(func.addr)
        func.endpoints = set([func.getNode(node.addr) for node in angr_function.endpoints if node is not None])
        func.endpoints_with_type = {type:set([func.getNode(node.addr) for node in nodes if node is not None]) for type, nodes in angr_function.endpoints_with_type.items()}
        func.has_return = angr_function.has_return
        func.has_unresolved_calls = angr_function.has_unresolved_calls
        func.has_unresolved_jumps = angr_function.has_unresolved_jumps
        func.is_plt = angr_function.is_plt
        func.is_syscall = angr_function.is_plt
        func.is_simprocedure = angr_function.is_simprocedure
        func.is_default_name = angr_function.is_default_name
        func.offset = angr_function.offset
        func.callees = set()
        func.is_recursive = False

        return func

    # Modifier
    def appendNode(self, node: CFGNode):
        pass

    def removeNode(self, node: CFGNode):
        pass

    def removeNodeByAddr(self, addr: int):
        pass

    # Accessor
    def getNode(self, addr: int):
        if addr not in self.nodes:
            return None
        return self.nodes[addr]

# 表示整个二进制文件的控制流图，包含多个节点和函数。通过添加和删除节点和函数来构建控制流图
class CFG:
    # [Attribute]
    #   angr_cfg                Original angr cfg object we build from.
    #   nodes                   A dict(addr:int -> node:CFGNode) of all nodes within this CFG.
    #   functions               A dict(name:str -> func:Function) of all function within this CFG.
    # [Member]
    #   get_node                Get CFG node by addr.

    # CFG类的构造函数。接受一个CFGFast对象作为参数，并创建一个新的CFG对象
    def __init__(self, angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> None:
        # Normalize this cfg first if not normalized.
        if not angr_cfg.normalized:
            angr_cfg.normalize()
        # Build CFG object.
        self.angr_cfg = angr_cfg
        # 保存所有的CFG节点对象，键是节点地址（address），值是对应的CFGNode对象
        self.nodes = dict()
        # 保存所有的函数对象，键是函数名称，值是对应的Function对象
        self.functions = dict()

    # Modifier 添加、删除 CFGNode Function 对象
    def appendCFGNode(self, node: CFGNode):
        if node.addr not in self.nodes:
            self.nodes[node.addr] = node
            return True
        return False
    
    def removeCFGNode(self, node: CFGNode):
        return self.removeCFGNodeByAddr(node.addr)
    
    def removeCFGNodeByAddr(self, addr: int):
        if addr in self.nodes:
            self.nodes.pop(addr)
            return True
        return False
    
    def appendFunction(self, func: Function):
        # nodes 是包含所有func.nodes和self.nodes中唯一元素的新集合
        name, nodes = func.name, func.nodes | self.nodes
        # 函数名称未存在过，且函数包含的节点也未存在过，则添加
        if name not in self.functions and len(nodes) == len(func.nodes) + len(self.nodes):
            self.functions[name] = func
            self.nodes = nodes
            return True
        return False

    def removeFunction(self, name: str):
        func = self.getFunc(name)
        if None == func:
            return False
        # 对于函数中的每个基本块地址，通过调用removeCFGNodeByAddr()方法来将其从nodes字典中删除
        for addr in func.nodes.keys():
            self.removeCFGNodeByAddr(addr)
        self.functions.pop(name)
        return True

    # Accessor
    def getAnyNode(self, addr: int):
        return self.nodes.get(addr)

    def getFunc(self, name: str):
        return self.functions.get(name)

    def getFuncByAddr(self, addr: int):
        for func in self.functions.values():
            if func.addr == addr:
                return func
        return None
