## ASSUMPTIONS:
- Input and binary file have the same name

## Google Doc Notes:
https://docs.google.com/document/d/1kjka3ijjtv6MdvxuVZKznp9sHsXN9ch6YZrAvmUkMf8/edit?tab=t.0#heading=h.rbnzp746ywxj

## Github Repo:
https://github.com/arctic-cheetah/COMP6447-Fuzzer

## System Diagram of fuzzer:
![](fuzzer-structure.png)

## 1) main.py file/Start point of Fuzzer:
```main.py``` This is the python module that starts the entire fuzzer program. It does the following:
1) It runs the harness, then harness deploys SHM memory.
2) For the ```x th``` given binary and input file, check the file type of the input file
3) Spawn a fuzzer based on the input file type, 
4) Run the fuzzer on the example input as a seed, and use mutation strategy from seed to generate random inputs
5) Record the crash in fuzzer_output



## 2) File Type Check:
```file_type_check.py``` this python module checks the file type of an input when paired with the given binary . It checks whether the input files is either:
- CSV
- JSON
- JPEG
- ELF
- PDF
- XML

If the input file does not match any of the above signatures and structures, then it is considered a text file (TXT)

### Mechanism:
- Use magic number to determine JPEG, ELF, PDF
- Use parser to check CSV or JSON
- ELSE txt


## 3) Fuzzer:
```Fuzzer.py``` 
Fuzzer uses a mutation-based strategy pattern to generate malformed/randomised output from valid seeds (input file) to cause crashes or abnormal behavior in target binaries. 

 Framework is modular: 
 - The function ```run_binary()``` handles the binary execution, (since harness is under work)
 - crash detection, and logging, 
 - Function pointers implement different mutator stragies which are chained together to produce randomise malformed output to the target binary

### Mechanism:

1) Seed input: Read valid seed files from /example_inputs/.

2) Mutation policy: For each iteration, apply 1–6 randomly selected mutators (via composition pattern), such as structural corruption, encoding-boundary stress, random byte insertion, truncation, pattern repetition, and deep nesting.

3) Execution model: Feed mutated inputs to the target binary (via file or stdin) using subprocess.run with a 1-second timeout (TODO: configurable).

4) Crash definition: A run is recorded as a crash if the process times out or exits with a negative return code (terminated by signal). Logged data include exit code, signal, stdout, stderr, and the seed/mutation trace.

5) Artifact preservation: On crash, write the responsible input to /fuzzer_output/bad_{progname}.txt to satisfy evaluation interfaces and enable deterministic replay.

Format file strategy pattern based mutators:

- JSON: 
    * unbalanced braces
    * duplicate keys
    * broken escapes 
    * illegal Unicode
    * extreme nesting
    * oversized strings.

- CSV: 
    * inconsistent columns
    * unusual delimiters
    * long UTF-8 sequences
    * repeated patterns
    * random byte insertions
    * truncations.

## 4) Harness:
``` hanress.cpp``` An incomplete implementation used to obtain code coverage, statistics, monitor process and run the binary. It is currently deployed in ```fuzzer.py``` because our part is complete

### Mechanism:
    - Start Harness and SHM
    - QEMU?? vs Ptrace
    - Need to implement code coverage

## Future TODOS:

Implement mutation strategy pattern for:
- JSON
- JPEG
- ELF
- PDF
- XML



