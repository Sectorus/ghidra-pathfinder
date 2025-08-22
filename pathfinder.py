# SymbolPathFinder.py
# @category Analysis
# @author Sectorus

from collections import deque
import java.io.File as File
import java.io.FileWriter as FileWriter
import java.io.PrintWriter as PrintWriter
import java.util.Date as Date

src_name = askString("Source Symbol", "Enter the source symbol name (e.g., DisplayMainMenu):")
if src_name is None:
    exit()

tgt_name = askString("Target Symbol", "Enter the target symbol name (e.g., Draw):")
if tgt_name is None:
    exit()

import java.lang.System as System
output_file = File(System.getProperty("user.home"), "ghidra_pathfinder_results.txt")
writer = PrintWriter(FileWriter(output_file))

def log_both(message):
    print(message)
    writer.println(message)
    writer.flush()

def getSymbolByName(name):
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getSymbols(name)
    for sym in symbols:
        return sym
    return None

def getAllSymbolsByName(name):
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getSymbols(name)
    return list(symbols)

def getCalledSymbols(symbol):
    """Get all symbols called/referenced by the given symbol"""
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
    else:
        refs = getReferencesFrom(symbol.getAddress())
        for ref in refs:
            if ref.getReferenceType().isCall() or ref.getReferenceType().isData():
                to_address = ref.getToAddress()
                to_sym = currentProgram.getSymbolTable().getPrimarySymbol(to_address)
                if to_sym and to_sym not in called and to_sym != symbol:
                    called.append(to_sym)
    return called

def find_paths(start_sym, target_sym, max_depth=15):
    """Find all paths from start_sym to target_sym using BFS"""
    paths = []
    queue = deque([[start_sym]])
    visited = set()

    while queue:
        path = queue.popleft()
        current = path[-1]

        if current == target_sym or current.getName() == target_sym.getName():
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
log_both("Source Symbol: {}".format(src_name))
log_both("Target Symbol: {}".format(tgt_name))
log_both("Generated: {}".format(java.util.Date()))
log_both("=" * 80)

log_both("Symbol Path Finder - Searching in {}".format(currentProgram.getName()))

src_symbols = getAllSymbolsByName(src_name)
tgt_symbols = getAllSymbolsByName(tgt_name)

if not src_symbols:
    log_both("Source symbol '{}' not found.".format(src_name))
    log_both("Available symbols containing '{}':".format(src_name))
    symbol_table = currentProgram.getSymbolTable()
    all_symbols = symbol_table.getAllSymbols(True)
    count = 0
    for sym in all_symbols:
        if src_name.lower() in sym.getName().lower() and count < 10:
            log_both("  - {}".format(sym.getName()))
            count += 1
    writer.close()
    exit()

if not tgt_symbols:
    log_both("Target symbol '{}' not found.".format(tgt_name))
    log_both("Available symbols containing '{}':".format(tgt_name))
    symbol_table = currentProgram.getSymbolTable()
    all_symbols = symbol_table.getAllSymbols(True)
    count = 0
    for sym in all_symbols:
        if tgt_name.lower() in sym.getName().lower() and count < 10:
            log_both("  - {}".format(sym.getName()))
            count += 1
    writer.close()
    exit()

log_both("Found {} source symbol(s) and {} target symbol(s)".format(len(src_symbols), len(tgt_symbols)))

all_paths = []
for src_sym in src_symbols:
    for tgt_sym in tgt_symbols:
        log_both("Searching from '{}' at {} to '{}' at {}...".format(
            src_sym.getName(), src_sym.getAddress(), 
            tgt_sym.getName(), tgt_sym.getAddress()))
        
        paths = find_paths(src_sym, tgt_sym)
        all_paths.extend(paths)

if not all_paths:
    log_both("No path found from {} to {}.".format(src_name, tgt_name))
    log_both("Try increasing max_depth or check if symbols are actually connected.")
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
