from abc import abstractmethod
from platform import node
import angr, CFGParser

# Save information for segment.
# A segment is a CFG.
class Segment(CFGParser.CFG):
    pass

# Save information for segment flow graph.
class SFG:
    pass

# A particular situation for segment flow graph.
class SegmentList(SFG):
    pass

class AbstractSFGParser:
    @abstractmethod
    def parseFromAngrCFG(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entry: int):
        pass

class AbstractSegmentListParser(AbstractSFGParser):
    # All segments found by this parser have same entry.

    def getReturnBlock(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entryNode):
        retblks = set()
        # Collect end point from return block.
        entryFunc = angrCFG.functions.get_by_addr(entryNode.function_address)
        for node in [angrCFG.get_any_node(addr) for addr in entryFunc.block_addrs_set]:
            if node.has_return:
                retblks.add(node)
        return retblks
    
    def getExitBlock(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast):
        exitpoint = set()
        exitFunc, _exitFunc = angrCFG.functions.get("exit"), angrCFG.functions.get("_exit")
        if exitFunc is not None:
            exitpoint.add(angrCFG.get_any_node(exitFunc.addr))
        if _exitFunc is not None:
            exitpoint.add(angrCFG.get_any_node(_exitFunc.addr))
        return exitpoint

    def defaultEndPoints(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entryNode):
        return self.getReturnBlock(angrCFG, entryNode) | self.getExitBlock(angrCFG)

    @abstractmethod
    def parseFromAngrCFG(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entry: int):
        pass

class PathSearchParser(AbstractSegmentListParser):
    def parseFromAngrCFG(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entry: int):
        # 1. Search path in DFS manner.
        #   1.1 When we met with circle, that means all nodes within this circle aren't candidate, we should remove these nodes from path.
        #   1.2 If path ends with expected node(eq to end or return node), save the rest nodes.
        # 2. The common nodes of all path are what we want.

        # Get the entry node.
        entryNode = angrCFG.get_any_node(entry)
        # Get all end points.
        endPoints = self.defaultEndPoints(angrCFG, entryNode)
        # DFS stack: (CFGNode, depth)
        bs, path = [(entryNode, 0)], []
        # candidates: {CFGNode: num}
        pathNum, candidates, circleNode = 0, {}, set([])
        while len(bs) > 0:
            curNode, depth = bs.pop()
            pathLen = len(path)
            # Update path, here curNode won't cause a circle.
            if depth < pathLen:
                path = path[0:depth]
            path.append(curNode)
            pathSet = set(path)
            # Debug.
            # print([hex(node.addr) for node in path])
            # Update bs for DFS.
            for successor in curNode.successors:
                # We met with a circle(successor-> ... -> curNode).
                if successor in pathSet:
                    for node in path[path.index(successor):-1]:
                        circleNode.add(node)
                # The path terminated when we met with endpoint.
                elif successor in endPoints:
                    # Debug.
                    # print([hex(node.addr) for node in path])
                    # Skip the entryNode.
                    for node in [validNode for validNode in path[1:] if validNode not in circleNode and validNode.size > 0]:
                        candidates.setdefault(node, 0)
                        candidates[node] += 1
                    pathNum += 1
                else:
                    bs.append((successor, depth+1))
        # Output node when candidates[node] == pathNum.
        return [node for node, num in candidates.items() if num == pathNum]

class BlockCheckParser(AbstractSegmentListParser):
    def isSeparateNode(self, targetNode, entryNode, endPoints: set):
        if targetNode == entryNode:
            return False
        # Get target set and entry set.
        targetSet = GraphTools.traversal(targetNode, lambda x: x.successors, lambda _: False)
        entrySet = GraphTools.traversal(entryNode, lambda x: x.successors, lambda x: x == targetNode)
        # targetNode is a separator only if targetSet & entrySet matchs a empty set.
        # Return valid targetNode.
        # return 0 != len(targetSet&endPoints) and 0 == len(targetSet&entrySet-endPoints)
        return 0 != len(targetSet&endPoints) and 0 == len(entrySet&endPoints) and 0 == len(targetSet&entrySet)

    def searchValidPath(self, entryNode, endPoints: set):
        # DFS stack: (CFGNode, depth)
        bs, path = [(entryNode, 0)], []
        while len(bs) > 0:
            curNode, depth = bs.pop()
            # Update path, here curNode won't cause a circle.
            if depth < len(path):
                path = path[0:depth]
            path.append(curNode)
            pathSet = set(path)
            # Update bs for DFS.
            for successor in curNode.successors:
                if successor in pathSet:
                    continue
                elif successor in endPoints:
                    # Debug.
                    print([hex(node.addr) for node in path])
                    return path
                else:
                    bs.append((successor, depth+1))
        return []

    @abstractmethod
    def parseFromAngrCFG(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entry: int):
        # 1. Find a path start with entry block and end with the node saticfies isEndpoint.
        # 2. Check each path node and collect those satisfy isSeperatorNode.

        # Get the entry node.
        entryNode = angrCFG.get_any_node(entry)
        # Get all end points.
        endPoints = self.defaultEndPoints(angrCFG, entryNode)
        # Search a valid path.
        path = angrCFG.nodes()
        # path = self.searchValidPath(entryNode, endPoints)
        # Collect all separate nodes.
        return [node for node in path if self.isSeparateNode(node, entryNode, endPoints)]

# Provides helper functions for graph operation.
class GraphTools:
    # Traversal whole graph begin with start node, return all node found.
    # [in]  start           Start point of the whole traversal.
    # [in]  getNeighbor     A function object provides a node list of current node which will be traveled in next iteration.
    # [in]  ignoreNeighbor  A function object tells us whether travel a node or not.
    # [out]                 A traveled node list.
    def traversal(start, getNeighbor, ignoreNeighbor) -> set:
        visit, stack = set([start]), [start]
        while len(stack) > 0:
            cur = stack.pop()
            for node in getNeighbor(cur):
                if node in visit or ignoreNeighbor(node):
                    continue
                visit.add(node)
                stack.append(node)
        return visit
