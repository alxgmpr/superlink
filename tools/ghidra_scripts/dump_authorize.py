# coding=utf-8
# Headless Ghidra script - dump decompilations + xrefs around the
# authorize.secret memcmp callsite (Y4 EXPECTED hunt).
#
# Run via:
#   analyzeHeadless <project> <name> \
#     -import lorabrd \
#     -postScript dump_authorize.py
#
# Writes /tmp/authorize_analysis.txt
#
# @category Lorabrd
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "/tmp/authorize_analysis.txt"

f = open(OUT, "w")

def out(s):
    f.write(s + "\n")

ds = DecompInterface()
ds.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()
rm = currentProgram.getReferenceManager()

# Known waypoints from prior RE (controller_y4_results.md, authorize_secret_validated.md)
TARGETS = [
    (0x5fdfc, "parser_authorize_handler (caller of secretbox_helper)"),
    (0x5fe14, "memcmp callsite inside parser_authorize_handler"),
    (0x3bfa8, "secretbox_helper (calls memcmp on decrypted PT vs EXPECTED)"),
    (0x2ffb8, "secretbox_open_easy wrapper (24B nonce, 32B key checks)"),
]

for addr_int, label in TARGETS:
    addr = af.getDefaultAddressSpace().getAddress(addr_int)
    fn = fm.getFunctionContaining(addr)
    if fn is not None:
        out("============================================================")
        out("=== %s @ 0x%x" % (label, addr_int))
        out("=== Function: %s @ %s  body 0x%x-0x%x" % (
            fn.getName(),
            fn.getEntryPoint(),
            fn.getBody().getMinAddress().getOffset(),
            fn.getBody().getMaxAddress().getOffset(),
        ))
        out("============================================================")
        result = ds.decompileFunction(fn, 60, ConsoleTaskMonitor())
        if result.decompileCompleted():
            out(result.getDecompiledFunction().getC())
        else:
            out("Decompilation failed: " + str(result.getErrorMessage()))
        out("")
    else:
        out("No function at 0x%x\n" % addr_int)

# Xrefs INTO the authorize chain — what calls these handlers?
out("")
out("============================================================")
out("=== XREFS")
out("============================================================")
for addr_int in [0x5fdfc, 0x3bfa8, 0x2ffb8]:
    addr = af.getDefaultAddressSpace().getAddress(addr_int)
    out("xrefs to 0x%x:" % addr_int)
    for ref in rm.getReferencesTo(addr):
        from_addr = ref.getFromAddress()
        from_fn = fm.getFunctionContaining(from_addr)
        from_name = from_fn.getName() if from_fn is not None else "?"
        out("  from %s  type=%s  in %s" % (
            from_addr, ref.getReferenceType(), from_name))
    out("")

# All functions whose name hints at the parser/authorize/secret/json layer
out("")
out("============================================================")
out("=== Candidate functions by name")
out("============================================================")
keywords = [
    "authorize", "Authorize", "secret", "Secret",
    "parser", "Parser", "parse",
    "nlohmann", "json",
    "clientID", "ClientID", "client",
    "challenge", "Challenge",
    "kdf", "KDF",
    "AuthToken", "authToken", "token",
    "salt", "Salt",
]
seen = set()
for fn in fm.getFunctions(True):
    name = fn.getName()
    for kw in keywords:
        if kw in name and name not in seen:
            seen.add(name)
            out("  %s @ %s" % (name, fn.getEntryPoint()))
            break

# Strings hinting at the protocol — "errorCode 4 Bad secret", clientID, etc.
out("")
out("============================================================")
out("=== Strings (filtered)")
out("============================================================")
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
data_iter = listing.getDefinedData(True)
str_keywords = [
    "secret", "Secret", "authorize", "Authorize",
    "Bad secret", "errorCode",
    "clientID", "ClientID",
    "AuthToken", "authToken",
    "UBNU",
    "lorabr", "ubnt_avclient",
    "salt", "Salt",
]
for d in data_iter:
    if d.hasStringValue():
        s = str(d.getValue())
        for kw in str_keywords:
            if kw in s:
                out("  %s : %r" % (d.getAddress(), s))
                break

# Globals/data items in the parser's likely vicinity
out("")
out("============================================================")
out("=== Top-level classes (RTTI-derived)")
out("============================================================")
sym = currentProgram.getSymbolTable()
ns_seen = set()
for s in sym.getDefinedSymbols():
    pname = s.getParentNamespace().getName(True)
    if "::" in pname and pname not in ns_seen:
        ns_seen.add(pname)
        out("  %s" % pname)
        if len(ns_seen) > 200:
            break

f.close()
print("Wrote " + OUT)
