## analysis.py

该项目是一个程序的辅助分析工具，提供了多个命令行工具来分析和处理程序的二进制文件和追踪文件。其中 `analysis.py` 提供了一些生成任务控制器的工具，实现基于追踪数据的划分和分析，并用于生成概率最大的最坏执行时间（p-WCET）分析结果。

## `CFG2Segment`
### CFG2Segment/CFGRefactor.py

这是一个 Python 代码文件，文件名为 CFGRefactor.py。它定义了一个名为 CFGRefactor 的类和其他几个继承自 CFGRefactor 的子类，每个子类都实现了 refactor 方法来重构 CFGBase.Function 对象。其中 FunctionRefactor 根据给定的控制流图节点，尝试使用 angr 库中的节点数据来创建一个新的 CFGBase.Function 对象。如果此重构失败，则该函数会将其添加到 failed 列表中。如果所有重构都成功，则返回 True。

### CFG2Segment/__init__.py

这是一个Python文件，命名为``__init__.py``，位于``PTATM-master/CFG2Segment``目录下。该文件是一个空文件，通常用于标识特定目录是Python包的一部分。它可以包含``import``语句来引入其他Python模块和包。

### CFG2Segment/Tool.py

这是一个名为Tool.py的Python脚本文件，其中定义了两个类GraphTool和SegmentSearcher，以及类GraphTool中的两个静态方法traversal和topologicalSort。方法traversal实现了图的遍历，方法topologicalSort实现了图的拓扑排序。类SegmentSearcher是一个抽象基类，其中定义了一个抽象方法search，而类PathCoverSearcher和BlockCheckSearcher则分别继承自SegmentSearcher类，实现了search方法，完成了对图的路径搜索和块的检查。每个方法和类都有相应的注释解释其作用。该脚本文件可能是一个代码静态分析实用工具库的一部分。

### CFG2Segment/SFGBuilder.py

该程序文件是Python语言编写的，其实现了一个静态分析工具中的控制流图（CFG）到段流图（SFG）的转换，其中包含了以下类：

1. SFGBuilder：抽象基类，定义了build方法，并设置了max_seg属性和setMaxSegment方法。
2. SFGReset：抽象基类，定义了reset方法。
3. SegmentFunctionReset：继承了SFGReset类，实现了reset方法，用于重置段函数的成员变量。
4. FunctionalSegmentListBuilder：继承了SFGBuilder类，实现了build和searchSeparator方法，用于构建函数的段流图。
5. ConcreteSFGReset：继承了SFGReset类，实现了reset方法，用于重置静态分析图（SFG）的成员变量。
6. FunctionalSFGBuilder：继承了SFGBuilder类，实现了build方法，用于构建SFG。

### CFG2Segment/CFGBase.py

这个程序文件实现了一个控制流图(CFG)和函数(Function)的相关操作，其中CFGNode类保存了基本块相关信息，Function类保存了函数相关信息。CFG类则是一个控制流图的集合，可以添加、移除基本块和函数。

### CFG2Segment/SFGBase.py

该程序文件定义了几个类来实现基于代码流图的程序控制流分析。其中，Segment类是基本的代码段类，其中包含段的名称、起始地址、前趋和后继等信息。SegmentFunction类是基于Segment类的代码段的功能类。它包含一个函数的所有段和一些有关函数的信息。SFG类是基于Segment类的代码段的流图类。它包含多个段和一些与段有关的信息。该文件的代码还包含一些与段名称和编号有关的实用函数。该代码文件假设同一个函数的段名称必须不同，因为它们以函数名称和段号作为名称的一部分。

## `SegmentInfoCollector`
### SegmentInfoCollector/Collector.py

该程序文件是一个Python脚本，名字为Collector.py。它依赖于Python的subprocess模块，为某个性能追踪系统收集程序运行时的跟踪信息。它的主要功能包括添加或删除程序运行时的监控探针，使用perf record命令和perf script命令，以及从perf script命令的输出中提取时间戳和代码段信息。具体而言，它提供了静态方法addprobe()和delprobe()用于添加探针和删除探针，collectTrace()方法用于收集程序的性能追踪信息，fetchSegmentAndTime()方法用于从追踪信息中提取需要的信息。

### SegmentInfoCollector/__init__.py

这个Python文件的作用是将上级目录添加到sys.path路径中，以便在其他Python文件中导入上级目录中的模块。

### SegmentInfoCollector/TraceTool.py

该程序文件是一个Python脚本，用于定义实现了分段函数类的跟踪类（Trace）和相关的填充类（TraceFiller）、序列化类（TraceSerializer）以及剥离类（TraceStripper）。其中跟踪类定义了一个跟踪对象，包含了一个命令集合、一组字典以及一个时间戳。填充类用于从外部数据源填充Trace对象；序列化类用于将Trace对象序列化为Json格式的字符串；剥离类用于从Trace对象中删除或修改一些字段。

## `test`
### test/SegmentBuildTest.py

该代码文件是一个 Python 脚本，使用了 angr 库，建立了一个程序在执行时的控制流图（CFG）。接着，使用了 CFG2Segment 库将 CFG 转化为基本块列表（Basic Block List）。然后，实例化了 CFG2Segment 库中的 FunctionalSFGBuilder 和 BlockCheckSearcher 类，用于构建和验证子函数的 SFG（Sub Function Graph）和块的合法性。最后，打印出了结果并输出到控制台。

### test/RefactorTest.py

这是一个Python脚本文件，其主要目的是使用`angr`库来进行程序分析。通过对不同的基准测试程序进行分析，获取函数间的控制流程，并对分析结果进行处理，输出处理后的控制流程。其中涉及到的基准测试程序主要来自于不同的应用领域，如汽车、办公、安全等领域，该脚本可以批处理所有基准测试程序并分析其控制流程。

### test/ParseSegment.py

该程序文件主要实现了以下功能：

1. 引入了sys和angr两个库
2. 定义了多个文件的路径，这些文件都属于MiBench基准测试集中的不同类别
3. 通过angr库将选定的文件加载为一个angr项目
4. 对项目的控制流图（CFG）进行快速分析，进而进行规范化操作
5. 获取main函数的地址，并使用BlockCheckParser从CFG中解析出main函数中所有基本块（basic block）的地址
6. 最后打印出基本块的地址信息

### test/genpwcet.py

该程序文件的作用是生成基于符号定时分析的pwcet估计或曲线以用于目标函数。该程序需要输入trace文件。程序有两个命令可选，依次是image和value，用于生成pwcet曲线和估计。还有一些选项，如定义目标函数，设置EVT类型、输出精度等等。程序还提供绘制isf图形的功能，其中isf = 1-cdf。

### test/dumptrace.py

这是一个Python程序文件，文件名为`dumptrace.py`。该程序解析原始或JSON形式的跟踪文件，从中获取段信息，并输出到标准输出或指定的输出文件中。程序包含三种处理模式，分别为`parse`，`merge`和`graph`。其基本工作流程为将原始跟踪数据填充到Trace对象中，然后对Trace对象进行处理以获取段信息和呼叫信息，并以JSON格式输出。程序依赖于SegmentInfoCollector.TraceTool模块。具体使用方法参见程序注释。

### test/genprobe.py

该文件是一个Python脚本，用于为感兴趣的函数生成段探针。它使用了angr模块来分析二进制文件，然后对CFG进行了重构，构建了SFG。接着，它移除不存在于SFG中的函数并从段信息中收集探针。最后，它输出了收集的探针。程序中涉及到了命令行参数，包括感兴趣的函数，最大段数等。

### test/gentrace.py

此程序文件是一个Python脚本，用于生成针对给定命令的探针跟踪。它使用argparse解析命令行参数，并允许用户指定用于插装的探针、跟踪周期和跟踪输出格式。它通过调用perf命令动态地添加和删除探针，重定向标准输出和标准错误以分别捕获跟踪信息和错误信息，并使用正则表达式提取纯粹的时间戳和段名。

## `PWCETGenerator`
### PWCETGenerator/EVTTool.py

该程序文件主要是一个极值分布工具，其中包括三个类：PWCETInterface, ExtremeDistribution和LinearCombinedExtremeDistribution，以及五个子类：GEV、GPD、PositiveLinearGumbel、PositiveLinearExponentialPareto、EVT。每个子类提供不同的生成和拟合极值分布的方法，适用于不同的情况和数据需求。该程序文件还包括一些工具函数来辅助生成或拟合极值分布。

### PWCETGenerator/PWCETSolver.py

该程序文件包含了一个Python代码实现，其主要功能是对符号轨迹进行线性组合建模。该代码实现由多个类组成，它们有不同的功能和目的。该代码实现中提供了抽象方法和定义，是设计高可扩展性架构的实现方式之一。

### PWCETGenerator/__init__.py

这个Python语言文件的文件名是`__init__.py`。它的作用是将上级目录添加到Python的搜索路径中，以便从其他模块中导入代码。具体来说，它使用`sys.path.append("..")`将上级目录添加到`sys.path`列表中。

## 概括程序的整体功能

| 文件名                                                         | 功能描述                                                     |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| PTATM-master.zip.extract/PTATM-master/analysis.py            | 提供了生成任务控制器的工具，实现基于追踪数据的划分和分析，用于生成概率最大的最坏执行时间（p-WCET）分析结果 |
| PTATM-master.zip.extract/PTATM-master/CFG2Segment/CFGRefactor.py | 定义了一个类和几个继承自这个类的子类，每个子类都实现了 refctor 方法来重构 CFGBase.Function 对象 |
| PTATM-master.zip.extract/PTATM-master/CFG2Segment/__init__.py | 空文件，用于标识特定目录是Python包的一部分              |
| PTATM-master.zip.extract/PTATM-master/CFG2Segment/Tool.py    | 定义了两个类 GraphTool 和 SegmentSearcher，其中类 GraphTool 中提供了 traversal 和 topologicalSort 两个方法 |
| PTATM-master.zip.extract/PTATM-master/CFG2Segment/SFGBuilder.py | 用于实现控制流图（CFG）到段流图（SFG）的转换             |
| PTATM-master.zip.extract/PTATM-master/CFG2Segment/CFGBase.py | 实现了一个控制流图（CFG）和函数（Function）的相关操作     |
| PTATM-master.zip.extract/PTATM-master/CFG2Segment/SFGBase.py | 实现了基于代码流图的程序控制流分析                         |
| PTATM-master.zip.extract/PTATM-master/SegmentInfoCollector/Collector.py | 用于为某个性能追踪系统收集程序运行时的跟踪信息             |
| PTATM-master.zip.extract/PTATM-master/SegmentInfoCollector/__init__.py | 将上级目录添加到sys.path路径中，以便在其他Python文件中导入上级目录中的模块 |
| PTATM-master.zip.extract/PTATM-master/SegmentInfoCollector/TraceTool.py | 实现了分段函数类的跟踪类和相关的填充类、序列化类以及剥离类 |
| PTATM-master.zip.extract/PTATM-master/test/SegmentBuildTest.py | 用于构建和验证子函数的SFG和块的合法性                      |
| PTATM-master.zip.extract/PTATM-master/test/RefactorTest.py   | 用于对不同的基准测试程序进行分析，获取函数间的控制流程，并对分析结果进行处理 |
| PTATM-master.zip.extract/PTATM-master/test/ParseSegment.py   | 从控制流图中解析出main函数中所有基本块的地址               |
| PTATM-master.zip.extract/PTATM-master/test/genpwcet.py       | 用于生成基于符号定时分析的pwcet估计或曲线以用于目标函数     |
| PTATM-master.zip.extract/PTATM-master/test/dumptrace.py      | 用于解析原始或JSON形式的跟踪文件，输出其中的段信息         |
| PTATM-master.zip.extract/PTATM-master/test/genprobe.py       | 用于为感兴趣的函数生成段探针                               |

程序整体功能为通过静态和动态分析，实现基于追踪数据的划分和分析，获取控制流程，进而达到精确计算程序最坏执行时间的目的。

## 程序整体功能概括

| 文件 | 功能 |
| ----- | ----- |
| analysis.py | 对基于信号流图的分段模型进行性能分析和探测分析 |
| CFGRefactor.py | 对控制流图进行重构，生成基于信号流图的分段模型 |
| __init__.py | 将上级目录添加到Python搜索路径中 |
| Tool.py | 提供一些常用的工具函数，如从源代码文件中提取函数、从AST树中查找节点等 |
| SFGBuilder.py | 构造基于信号流图的分段模型，将控制流图转换为信号流图 |
| CFGBase.py | 定义了表示控制流图的类 |
| SFGBase.py | 定义了表示信号流图的类 |
| Collector.py | 从分段模型中收集相关信息，并输出为JSON格式 |
| TraceTool.py | 用于将perf工具跟踪信息转换为JSON格式 |
| SegmentBuildTest.py | 对信号流图分段模型的构建进行测试 |
| RefactorTest.py | 对控制流图重构为信号流图的过程进行测试 |
| ParseSegment.py | 对信号流图分段模型文件进行解析，并进行一些处理 |
| genpwcet.py | 生成程序的PWCET |
| dumptrace.py | 以可读格式转储perf工具的跟踪信息 |
| genprobe.py | 生成探针，并将其插入程序中 |
| gentrace.py | 生成探针跟踪 |
| EVTTool.py | 实现极值分布的生成和拟合工具 |
| PWCETSolver.py | 对符号轨迹进行线性组合建模 |
 
这是一个性能分析工具，将程序分为多个片段并分析它们的性能。