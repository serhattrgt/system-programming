# System Programming Project

This project consists of two advanced system programming tools developed in C for Linux environments:

1.  **Memory Analyzer (`q1`)**: A tool to analyze process memory segments, virtual/physical memory usage, and detect memory leaks.
2.  **Code Safety Analyzer (`q2`)**: A static analysis tool to detect security vulnerabilities (unsafe functions, buffer overflows, format string attacks, etc.) in C source code.

## Project Structure

```
├── build/                  # Compiled executables (created after make)
├── src/
│   ├── q1/                 # Memory Analyzer source code
│   │   ├── implementation/
│   │   └── header/
│   ├── q2/                 # Code Safety Analyzer source code
│   │   ├── implementation/
│   │   └── header/
│   └── common/
├── tests/
│   └── samples/            # Sample C files for testing Q2
└── Makefile                # Build script
```

## How to Build

The project uses a `Makefile` for compilation. Run the following command in the project root:

```bash
make
```

To clean build artifacts:
```bash
make clean
```

*Note: If you are using Windows, ensure you run these commands within **WSL (Windows Subsystem for Linux)**.*

## Usage

### 1. Advanced Process Memory Analyzer (`q1`)

This tool analyzes its own memory usage.

*   **Basic Analysis**: View memory segments (Text, Data, Heap, Stack) and usage stats.
    ```bash
    ./build/q1
    ```

*   **Monitor Mode**: Continuously monitor memory usage (refresh every N seconds).
    ```bash
    ./build/q1 --monitor 2
    ```

*   **Leak Check**: Run a demonstration of the built-in memory leak detector.
    ```bash
    ./build/q1 --leak-check
    ```

*   **All Features**: Run all analyses at once.
    ```bash
    ./build/q1 --all
    ```

### 2. Advanced Code Safety Analyzer (`q2`)

This tool scans **other C files** for vulnerabilities.

*   **Scan Mode (`-s`)**: Lists unsafe functions (e.g., `strcpy`, `gets`) with line numbers.
    ```bash
    ./build/q2 -s tests/samples/vulnerable1.c
    ```

*   **Recommendation Mode (`-r`)**: Explains vulnerabilities and suggests safer alternatives (e.g., "Use `fgets` instead of `gets`").
    ```bash
    ./build/q2 -r tests/samples/vulnerable1.c
    ```

*   **Extended Check (`-x`)**: Scans for complex vulnerabilities like Format String attacks, Command Injection, and Integer Overflow risks.
    ```bash
    ./build/q2 -x tests/samples/vulnerable2.c
    ```

## Functionality Details

### App 1 (`q1`) Logic
- Parses `/proc/self/maps` to identify memory segments.
- Parses `/proc/self/status` to calculate Virtual vs Physical memory efficiency.
- Uses a custom wrappers (`tracked_malloc`, `tracked_free`) to track allocations and report leaks upon exit.

### App 2 (`q2`) Logic
- Reads the target C file line by line.
- **Scan/Rec Mode**: Searches for known unsafe tokens (`strcpy`, `strcat`, `time` functions).
- **Extended Mode**: Applies heuristics to detect:
    - **Format String**: `printf(var)` usage without format specifiers.
    - **Command Injection**: Usage of `system()` or `popen()`.
    - **Integer Overflow**: Patterns like `malloc(n * size)`.
