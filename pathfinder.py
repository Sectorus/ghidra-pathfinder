# pathfinder.py
# @category Analysis
# @author Sectorus

from collections import deque
import java.io.File as File
import java.io.FileWriter as FileWriter
import java.io.PrintWriter as PrintWriter
import java.util.Date as Date

src_input = askString("Source", "Enter source symbol name or address (e.g., DisplayMainMenu or 0x401000):")
if src_input is None:
    exit()

tgt_input = askString("Target", "Enter target symbol name or address (e.g., Draw or 0x402000):")
if tgt_input is None:
    exit()

import java.lang.System as System
output_file = File(System.getProperty("user.home"), "ghidra_pathfinder_results.txt")
writer = PrintWriter(FileWriter(output_file))

def log_both(message):
    print(message)
    writer.println(message)
    writer.flush()

def parseInput(input_str):
    """Parse input as either symbol name or address"""
    if input_str.startswith("0x") or input_str.startswith("0X"):
        try:
            addr = currentProgram.getAddressFactory().getAddress(input_str)
            return "address", addr
        except:
            return "invalid", None
    elif all(c in "0123456789ABCDEFabcdef" for c in input_str):
        try:
            addr = currentProgram.getAddressFactory().getAddress("0x" + input_str)
            return "address", addr
        except:
            return "symbol", input_str
    else:
        return "symbol", input_str

def getSymbolsFromInput(input_str):
    """Get symbols from either symbol name or address"""
    input_type, value = parseInput(input_str)
    
    if input_type == "invalid":
        return []
    elif input_type == "address":
        symbol = currentProgram.getSymbolTable().getPrimarySymbol(value)
        if symbol:
            return [symbol]
        else:
            class PseudoSymbol:
                def __init__(self, address):
                    self.address = address
                def getName(self):
                    return "addr_{}".format(self.address)
                def getAddress(self):
                    return self.address
                def __eq__(self, other):
                    return hasattr(other, 'getAddress') and self.address == other.getAddress()
                def __hash__(self):
                    return hash(str(self.address))
            return [PseudoSymbol(value)]
    else:
        symbol_table = currentProgram.getSymbolTable()
        symbols = symbol_table.getSymbols(value)
        return list(symbols)

def getCalledSymbols(symbol):
    called = []
    listing = currentProgram.getListing()

    func = getFunctionContaining(symbol.getAddress())
    if func is not None:
        instr_iter = listing.getInstructions(func.getBody(), True)
        for instr in instr_iter:
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType().isCall() or ref.getReferenceType().isData():
                    to_address = ref.getToAddress()
                    to_sym = currentProgram.getSymbolTable().getPrimarySymbol(to_address)
                    if to_sym and to_sym not in called and to_sym != symbol:
                        called.append(to_sym)
                    elif not to_sym and to_address != symbol.getAddress():
                        # Create pseudo-symbol for addresses without symbols
                        class PseudoSymbol:
                            def __init__(self, address):
                                self.address = address
                            def getName(self):
                                return "addr_{}".format(self.address)
                            def getAddress(self):
                                return self.address
                            def __eq__(self, other):
                                return hasattr(other, 'getAddress') and self.address == other.getAddress()
                            def __hash__(self):
                                return hash(str(self.address))
                        pseudo_sym = PseudoSymbol(to_address)
                        if pseudo_sym not in called:
                            called.append(pseudo_sym)
    else:
        refs = getReferencesFrom(symbol.getAddress())
        for ref in refs:
            if ref.getReferenceType().isCall() or ref.getReferenceType().isData():
                to_address = ref.getToAddress()
                to_sym = currentProgram.getSymbolTable().getPrimarySymbol(to_address)
                if to_sym and to_sym not in called and to_sym != symbol:
                    called.append(to_sym)
                elif not to_sym and to_address != symbol.getAddress():
                    class PseudoSymbol:
                        def __init__(self, address):
                            self.address = address
                        def getName(self):
                            return "addr_{}".format(self.address)
                        def getAddress(self):
                            return self.address
                        def __eq__(self, other):
                            return hasattr(other, 'getAddress') and self.address == other.getAddress()
                        def __hash__(self):
                            return hash(str(self.address))
                    pseudo_sym = PseudoSymbol(to_address)
                    if pseudo_sym not in called:
                        called.append(pseudo_sym)
    return called

def find_paths(start_sym, target_sym, max_depth=15):
    paths = []
    queue = deque([[start_sym]])
    visited = set()

    while queue:
        path = queue.popleft()
        current = path[-1]

        # Check for match (symbol or address)
        if current == target_sym or current.getName() == target_sym.getName() or current.getAddress() == target_sym.getAddress():
            paths.append(path)
            continue

        if current in visited or len(path) > max_depth:
            continue

        visited.add(current)

        for called_sym in getCalledSymbols(current):
            if called_sym not in path:
                new_path = list(path)
                new_path.append(called_sym)
                queue.append(new_path)

    return paths

log_both("=" * 80)
log_both("GHIDRA SYMBOL PATH FINDER RESULTS")
log_both("=" * 80)
log_both("Program: {}".format(currentProgram.getName()))
log_both("Source: {}".format(src_input))
log_both("Target: {}".format(tgt_input))
log_both("Generated: {}".format(java.util.Date()))
log_both("=" * 80)

log_both("Symbol Path Finder - Searching in {}".format(currentProgram.getName()))

src_symbols = getSymbolsFromInput(src_input)
tgt_symbols = getSymbolsFromInput(tgt_input)

if not src_symbols:
    log_both("Source '{}' not found or invalid.".format(src_input))
    src_type, _ = parseInput(src_input)
    if src_type == "symbol":
        log_both("Available symbols containing '{}':".format(src_input))
        symbol_table = currentProgram.getSymbolTable()
        all_symbols = symbol_table.getAllSymbols(True)
        count = 0
        for sym in all_symbols:
            if src_input.lower() in sym.getName().lower() and count < 10:
                log_both("  - {} @ {}".format(sym.getName(), sym.getAddress()))
                count += 1
    writer.close()
    exit()

if not tgt_symbols:
    log_both("Target '{}' not found or invalid.".format(tgt_input))
    tgt_type, _ = parseInput(tgt_input)
    if tgt_type == "symbol":
        log_both("Available symbols containing '{}':".format(tgt_input))
        symbol_table = currentProgram.getSymbolTable()
        all_symbols = symbol_table.getAllSymbols(True)
        count = 0
        for sym in all_symbols:
            if tgt_input.lower() in sym.getName().lower() and count < 10:
                log_both("  - {} @ {}".format(sym.getName(), sym.getAddress()))
                count += 1
    writer.close()
    exit()

log_both("Found {} source(s) and {} target(s)".format(len(src_symbols), len(tgt_symbols)))

all_paths = []
for src_sym in src_symbols:
    for tgt_sym in tgt_symbols:
        log_both("Searching from '{}' at {} to '{}' at {}...".format(
            src_sym.getName(), src_sym.getAddress(), 
            tgt_sym.getName(), tgt_sym.getAddress()))
        
        paths = find_paths(src_sym, tgt_sym)
        all_paths.extend(paths)

if not all_paths:
    log_both("No path found from {} to {}.".format(src_input, tgt_input))
    log_both("Try increasing max_depth or check if symbols/addresses are actually connected.")
else:
    all_paths.sort(key=lambda path: len(path))
    
    log_both("\nFound {} total path(s) (sorted by hops, shortest first):".format(len(all_paths)))
    log_both("")
    
    for i, path in enumerate(all_paths, 1):
        hops = len(path) - 1
        log_both("PATH {} ({} hops):".format(i, hops))
        log_both("-" * 50)
        for j, sym in enumerate(path):
            indent = "  " * j
            if j == 0:
                log_both("{}START: {} @ {}".format(indent, sym.getName(), sym.getAddress()))
            elif j == len(path) - 1:
                log_both("{}END:   {} @ {}".format(indent, sym.getName(), sym.getAddress()))
            else:
                log_both("{}{}. {} @ {}".format(indent, j, sym.getName(), sym.getAddress()))
        log_both("")
        
    log_both("SUMMARY (Sorted by Hops):")
    log_both("-" * 60)
    log_both("Path#  Hops  Start -> End")
    log_both("-" * 60)
    
    for i, path in enumerate(all_paths, 1):
        hops = len(path) - 1
        log_both("{}      {}     {} -> {}".format(
            str(i).ljust(6), 
            str(hops).ljust(5), 
            path[0].getName(), 
            path[-1].getName()))
    
    log_both("")
    log_both("STATISTICS:")
    log_both("-" * 30)
    hop_counts = {}
    for path in all_paths:
        hops = len(path) - 1
        hop_counts[hops] = hop_counts.get(hops, 0) + 1
    
    for hops in sorted(hop_counts.keys()):
        log_both("{} hop(s): {} path(s)".format(hops, hop_counts[hops]))
    
    log_both("Shortest path: {} hops".format(len(all_paths[0]) - 1))
    log_both("Longest path: {} hops".format(len(all_paths[-1]) - 1))

log_both("")
log_both("=" * 80)
log_both("Results saved to: {}".format(output_file.getAbsolutePath()))
log_both("=" * 80)

writer.close()
popup("Analysis Complete!\n\nResults saved to:\n{}\n\nPaths sorted by hops (shortest first)".format(output_file.getAbsolutePath()))
