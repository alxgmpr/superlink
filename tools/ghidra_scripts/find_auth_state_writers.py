# coding=utf-8
# Find what writes to auth_state[+0x48] and [+0x3c] (the EXPECTED + NEXT_SECRET
# vectors used by lorabrd's authorize.secret memcmp).
#
# Strategy:
#   - Decompile callers of FUN_0005f8b0 (parser_authorize_handler) to find the
#     parser/connection-state object lifecycle.
#   - Decompile FUN_0003bf58 (the NEXT_SECRET getter) to understand the struct.
#   - Scan all functions for writes to offset 0x48 OR 0x3c of a pointer arg.
#   - Find xrefs to the vtable-like data pointers seen at heap+0x24..0x34
#     (0x118474, 0x118468, 0x118df4, 0x118de8) — those identify the class.
#
# @category Lorabrd
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "/tmp/auth_state_writers.txt"

f = open(OUT, "w")
def out(s):
    f.write(s + "\n")

ds = DecompInterface()
ds.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()
rm = currentProgram.getReferenceManager()
listing = currentProgram.getListing()

def addr(x):
    return af.getDefaultAddressSpace().getAddress(x)

def decomp_at(label, addr_int):
    a = addr(addr_int)
    fn = fm.getFunctionContaining(a)
    if fn is None:
        out("(%s) no function at 0x%x" % (label, addr_int))
        return None
    out("=" * 60)
    out("=== %s @ 0x%x" % (label, addr_int))
    out("=== Function: %s @ %s  body 0x%x-0x%x" % (
        fn.getName(),
        fn.getEntryPoint(),
        fn.getBody().getMinAddress().getOffset(),
        fn.getBody().getMaxAddress().getOffset(),
    ))
    out("=" * 60)
    result = ds.decompileFunction(fn, 60, ConsoleTaskMonitor())
    if result.decompileCompleted():
        out(result.getDecompiledFunction().getC())
    else:
        out("Decompilation failed")
    out("")
    return fn

# 1. Callers of FUN_0005f8b0 (parser_authorize_handler) - decompile each
out("############################################################")
out("# CALLERS OF FUN_0005f8b0 (parser_authorize_handler)")
out("############################################################")
fn_pah = fm.getFunctionAt(addr(0x5f8b0))
if fn_pah:
    callers = set()
    for ref in rm.getReferencesTo(addr(0x5f8b0)):
        from_addr = ref.getFromAddress()
        from_fn = fm.getFunctionContaining(from_addr)
        if from_fn:
            callers.add(from_fn.getEntryPoint().getOffset())
    out("callers count: %d" % len(callers))
    for caller_addr in sorted(callers):
        decomp_at("caller of FUN_0005f8b0", caller_addr)
else:
    out("FUN_0005f8b0 not found")

# 2. Decompile FUN_0003bf58 (the function that uses auth_state[+0x3c])
decomp_at("FUN_0003bf58 (uses auth_state+0x3c, NEXT_SECRET getter)", 0x3bf58)

# 3. Scan all functions for instructions that write to offset 0x48 OR 0x3c of a base register.
#    Pattern: STR Rs, [Rb, #0x48] or similar.
#    Simpler approach: search for immediate value 0x48 in code that's also near a STR.
out("")
out("############################################################")
out("# CANDIDATE WRITERS (functions touching offsets 0x3c or 0x48)")
out("############################################################")
out("Heuristic: function disassembly contains both '#0x3c' and '#0x48'")
out("(both fields of the auth_state struct used together)")
out("")

candidates_3c_48 = []
candidates_3c_only = []
candidates_48_only = []
for fn in fm.getFunctions(True):
    instructions = listing.getInstructions(fn.getBody(), True)
    found_3c = False
    found_48 = False
    for ins in instructions:
        s = str(ins).lower()
        if "0x3c" in s and ("str" in s or "ldr" in s):
            found_3c = True
        if "0x48" in s and ("str" in s or "ldr" in s):
            found_48 = True
        if found_3c and found_48:
            break
    if found_3c and found_48:
        candidates_3c_48.append(fn)
    elif found_3c:
        candidates_3c_only.append(fn)
    elif found_48:
        candidates_48_only.append(fn)

out("Functions with BOTH 0x3c and 0x48 ldr/str (most likely auth_state writers):")
for fn in candidates_3c_48:
    out("  %s @ %s" % (fn.getName(), fn.getEntryPoint()))
out("")
out("Functions with only 0x3c (count=%d, top 30):" % len(candidates_3c_only))
for fn in candidates_3c_only[:30]:
    out("  %s @ %s" % (fn.getName(), fn.getEntryPoint()))
out("")
out("Functions with only 0x48 (count=%d, top 30):" % len(candidates_48_only))
for fn in candidates_48_only[:30]:
    out("  %s @ %s" % (fn.getName(), fn.getEntryPoint()))

# 4. xrefs to the candidate vtable data pointers seen in heap dump
out("")
out("############################################################")
out("# XREFS TO CANDIDATE VTABLE/RTTI ADDRESSES (from heap dump)")
out("############################################################")
for vtable_addr in [0x118474, 0x118468, 0x118df4, 0x118de8, 0x16ad78, 0x16ad68]:
    a = addr(vtable_addr)
    out("xrefs to 0x%x:" % vtable_addr)
    refs = rm.getReferencesTo(a)
    cnt = 0
    for ref in refs:
        from_addr = ref.getFromAddress()
        from_fn = fm.getFunctionContaining(from_addr)
        from_name = from_fn.getName() if from_fn else "?"
        out("  from %s  type=%s  in %s" % (
            from_addr, ref.getReferenceType(), from_name))
        cnt += 1
        if cnt > 8: break
    if cnt == 0:
        out("  (no xrefs)")
    out("")

# 5. Decompile the top candidates
out("")
out("############################################################")
out("# DECOMPILATION OF TOP CANDIDATES (both 0x3c+0x48)")
out("############################################################")
for fn in candidates_3c_48[:10]:
    decomp_at("CANDIDATE: %s" % fn.getName(), fn.getEntryPoint().getOffset())

f.close()
print("Wrote %s" % OUT)
