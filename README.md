# Ghidra Symbol Path Finder

A Ghidra script that finds execution paths between two symbols in a binary. This tool helps reverse engineers understand how code flows from one function/method to another by analyzing call graphs and symbol references.

## Features

- **Symbol-based Analysis**: Works with any symbol in the binary (functions, methods, variables)
- **Path Discovery**: Uses breadth-first search to find all possible execution paths
- **Sorted Results**: Paths are sorted by hop count (shortest paths first)
- **Detailed Output**: Shows call hierarchy with addresses and indentation
- **File Export**: Results are saved to a text file for detailed analysis
- **Statistics**: Provides path distribution and complexity metrics

## How to Run in Ghidra

1. **Install the Script**:
   - Save the script as `pathfinder.py` in your Ghidra scripts directory
   - Default location: `$USER_HOME/ghidra_scripts/`

2. **Open Ghidra**:
   - Load your binary/program
   - Open the **Script Manager** via **Window → Script Manager**

3. **Run the Script**:
   - Find `pathfinder.py` in the script list
   - Click the green **Run Script** button
   - Enter your **source symbol name** (e.g., `DisplayMainMenu`)
   - Enter your **target symbol name** (e.g., `Draw`)

4. **View Results**:
   - Check the console for a summary
   - Full results are saved to `ghidra_pathfinder_results.txt` in your home directory
   - A popup will show the file location when complete

## Example Usage

**Input**: 
- Source Symbol: `DisplayMainMenu`
- Target Symbol: `Draw`

**Output**:
