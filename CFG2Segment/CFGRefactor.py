from abc import abstractmethod
from . import CFGBase
import angr


class CFGRefactor:
    # 抽象方法，对给定目标进行重构，由子类实现
    @abstractmethod
    def refactor(self, target) -> bool:
        pass

# 将给定的Function对象重置为其初始状态，即清空其所有成员变量


class FunctionReset(CFGRefactor):
    def refactor(self, target: CFGBase.Function) -> bool:
        # Type checking.
        if not isinstance(target, CFGBase.Function):
            return False

        # Reset target members. 清空 Function 的所有list
        target.callees.clear()
        for node in target.nodes.values():
            node.predecessors.clear()
            node.successors.clear()

        return True


class FunctionRefactor(CFGRefactor):
    def __init__(self):
        super().__init__()
        # Save unsolved angr block nodes for each refactor.
        self.unresolved_block = list()
        # Save angr block nodes that aren't exist in target.node_addrs_set.
        self.nonexisted_block = list()
        # Save addr whose block cannot be attached by angr_function.get_node.
        self.emptyblock_addr = list()

    # This refactor simply considers that indirect call always returns to the next block directly.
    def refactor(self, target: CFGBase.Function):
        '''
        对给定函数（即目标）进行CFG重构，使得所有间接调用（indirect call）的返回路径都直接返回到下一个块
        Args：
            target: 要进行重构的目标函数，类型为CFGBase.Function
        Return：
            重构成功返回True，否则返回False
        '''
        # Type checking.
        if not isinstance(target, CFGBase.Function):
            return False

        # Reset target.
        FunctionReset().refactor(target)

        # Reset status.
        self.unresolved_block.clear()
        self.nonexisted_block.clear()
        self.emptyblock_addr.clear()

        # Do refactor for each node.
        for node in target.nodes.values():
            # 获取node对应的angrNode
            angrNode = target.angr_function.get_node(node.addr)
            if angrNode is None:
                # We cannot get node for this addr. 表示无法获取该地址的节点
                # This may appear in function whose is_simprocedure is True.
                self.emptyblock_addr.append(node.addr)
                # TODO: Maybe we should remove this node from target.nodes?
            else:
                # Deal with each successor.
                # Case 1: 如果successor是普通块，则链接到当前节点。
                # Case 2: 如果successor的addr等于target的addr，则target是递归函数。如果successor是函数，则将该函数添加到callees中。
                # Case 3: 如果successor是其他类型的，则将其添加到unresolved_block中。
                for successor in angrNode.successors():
                    # Case 1: general block.
                    if isinstance(successor, angr.codenode.BlockNode):
                        successorNode = target.getNode(successor.addr)
                        if successorNode is not None:
                            # Link to this node.
                            node.appendSuccessor(successorNode)
                        else:
                            # Add it to nonexisted_block.
                            self.nonexisted_block.append(successor)
                    # Case 2: function.
                    elif isinstance(successor, angr.knowledge_plugins.functions.function.Function):
                        # Link to a function, add it to callees if successor.addr != target.addr.
                        if successor.addr == target.addr:
                            target.is_recursive = True
                        else:
                            target.callees.add(successor.addr)
                    # Case 3: other.
                    else:
                        # Add to unresolved_block.
                        self.unresolved_block.append(successor)
            if len(node.successors) == 0:
                # 将没有后继的节点添加到endpoints中
                target.endpoints.add(node)

        # Remove None node from endpoints.
        if None in target.endpoints:
            target.endpoints.remove(None)

        # Return false if this CFG isn't a valid CFG.
        # 存在起始点和终止点
        return None != target.startpoint and 0 != len(target.endpoints)


class FunctionCFGReset(CFGRefactor):
    def refactor(self, target: CFGBase.CFG):
        # Type checking.
        if not isinstance(target, CFGBase.CFG):
            return False

        # Reset target members.
        target.nodes.clear()
        target.functions.clear()

        return True


class FunctionalCFGRefactor(CFGRefactor):
    def __init__(self):
        super().__init__()
        # Save failed function object for each refactor.
        self.failed = list()
        # Save passed function object for each refactor.
        self.passed = list()

    def refactor(self, target: CFGBase.CFG):
        # Type checking.
        if not isinstance(target, CFGBase.CFG):
            return False

        # Reset target.
        FunctionCFGReset().refactor(target)

        # Reset status.
        self.failed.clear()
        self.passed.clear()

        # Do refactor for each function.
        for angrFunc in target.angr_cfg.functions.values():
            # Build function object.
            func = CFGBase.Function.fromAngrFunction(angrFunc, target.angr_cfg)
            # 如果此函数是plt函数、具有未解决的跳转、是simprocedure或is_default_name或size为0，则跳过该函数
            if func.is_plt or func.has_unresolved_jumps or func.is_simprocedure or func.is_default_name or 0 == func.size:
                # Ignore plt function and those who has unresolved jumps.
                self.passed.append(func)
            else:
                # Refactor the function object.
                if not FunctionRefactor().refactor(func) or not target.appendFunction(func):
                    self.failed.append(func)
        return 0 == len(self.failed)
