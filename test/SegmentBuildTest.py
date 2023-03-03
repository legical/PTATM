import sys
sys.path.append("..")

import angr
from CFG2Segment.CFGBase import *
from CFG2Segment.SFGBase import *
from CFG2Segment.CFGRefactor import *
from CFG2Segment.SFGBuilder import *
from CFG2Segment.Tool import *

# automotive
basicmath_large = "/home/pzy/project/mibench/automotive/basicmath/basicmath_large"
basicmath_small = "/home/pzy/project/mibench/automotive/basicmath/basicmath_small"
bitcnts = "/home/pzy/project/mibench/automotive/bitcount/bitcnts"
qsort_large = "/home/pzy/project/mibench/automotive/qsort/qsort_large"
qsort_small = "/home/pzy/project/mibench/automotive/qsort/qsort_small"
susan = "/home/pzy/project/mibench/automotive/susan/susan"
# consumer
# jpeg = "/home/pzy/project/mibench/consumer/jpeg/jpeg-6a/cjpeg"
# lame = "/home/pzy/project/mibench/consumer/lame/lame3.70/lame"
# mad = "/home/pzy/project/mibench/consumer/mad/mad-0.14.2b/madplay"
# network
dijkstra_large = "/home/pzy/project/mibench/network/dijkstra/dijkstra_large"
dijkstra_small = "/home/pzy/project/mibench/network/dijkstra/dijkstra_small"
# office
search_large = "/home/pzy/project/mibench/office/stringsearch/search_large"
search_small = "/home/pzy/project/mibench/office/stringsearch/search_small"
# security
bf = "/home/pzy/project/mibench/security/blowfish/bf"
sha = "/home/pzy/project/mibench/security/sha/sha"
# telecomm
adpcm = "/home/pzy/project/mibench/telecomm/adpcm/bin/rawcaudio"
crc = "/home/pzy/project/mibench/telecomm/CRC32/crc"
fft = "/home/pzy/project/mibench/telecomm/FFT/fft"
gsm_toast = "/home/pzy/project/mibench/telecomm/gsm/bin/toast"
gsm_untoast = "/home/pzy/project/mibench/telecomm/gsm/bin/untoast"

benchmark = "/home/pzy/project/PTATM/benchmark/benchmark"
test = "/home/pzy/project/PTATM/benchmark/test"

p = angr.Project("/usr/local/software/spec2017/benchspec/CPU/557.xz_r/run/run_base_refrate_mytest-m64.0000/xz_r_base.mytest-m64", load_options={'auto_load_libs': False})
cfg = p.analyses.CFGFast()
mycfg = CFG.fromAngrCFG(cfg)

refactor = FunctionalCFGRefactor()
print(refactor.refactor(mycfg))
# print([hex(func.addr) for func in refactor.failed])

main = mycfg.getFunc("main")
# print([hex(end.addr) for end in mycfg.getFunc("main").endpoints])

# segBuilder = FunctionalSegmentListBuilder(2)
# smain = SegmentFunction(main)
# print("build result:", segBuilder.build(smain))
# print("err seps:", [hex(addr) for addr in segBuilder.error_seps])
# print("seps:", [hex(addr) for addr in segBuilder.separators])
# print("len(segments):", len(smain.segments))
# print("segments:")
# for seg in smain.segments:
#     print(seg.name + " " + hex(seg.startpoint.addr))

sfgBuilder = FunctionalSFGBuilder(2, ["main"])
sfg = SFG(mycfg)
print("build result:", sfgBuilder.build(sfg))
print("build failed func:", sfgBuilder.build_failed)
print("append failed func:", sfgBuilder.append_failed)
print("all segs:", list(sfg.segments.keys()))

result = BlockCheckSearcher().search(main.startpoint, set(main.endpoints), lambda x: x.successors)
result_addr = [hex(node.addr) for node in result]
result_addr.sort()
print(result_addr)
