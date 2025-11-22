# 6447 Fuzzer Writeup

## Assumptions

- Assume input and binary files have the same base name
- Assume input format must be one of `JSON`, `XML`, `CSV`, `JPEG`, `ELF`, `PDF` or `Plaintext`
- Here `Plaintext` is the special non-of-the-above catch-all format
  (see also [Adam's reply](https://discourse02.cse.unsw.edu.au/25T3/COMP6447/t/resolved-plaintext3-is-not-plaintext/92))

## Notes

Some of the notes can be found here:
- https://docs.google.com/document/d/1kjka3ijjtv6MdvxuVZKznp9sHsXN9ch6YZrAvmUkMf8/view

## Github Repo

Source code and other notes can be found here:
- https://github.com/arctic-cheetah/COMP6447-Fuzzer

Our latest Github CI log can be found in:
- https://productionresultssa17.blob.core.windows.net/actions-results/6789d126-8e0f-407f-a60c-e9997240ba1c/workflow-job-run-e95e421a-4dc9-5b68-8003-639f144b203d/logs/job/job-logs.txt?rsct=text%2Fplain&se=2025-11-22T04%3A33%3A31Z&sig=tCJ9oOclQ%2BIVqX5JrSawwldGn9YClIRn1r7b2lwrpnY%3D&ske=2025-11-22T14%3A33%3A00Z&skoid=ca7593d4-ee42-46cd-af88-8b886a2f84eb&sks=b&skt=2025-11-22T02%3A33%3A00Z&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skv=2025-11-05&sp=r&spr=https&sr=b&st=2025-11-22T04%3A23%3A26Z&sv=2025-11-05

## System Diagram of Fuzzer

On the high level, the structure of our fuzzer can be approximated by the following system diagram:
![](fuzzer-structure.png)

## System Overview

### Running the fuzzer

Please use the provided `run_fuzzer.sh` script.

### Entry point

Source: `main.py`

This is the python module that starts the entire fuzzer program. It does the following:

1. It runs the harness, then harness deploys shared memory.
2. For the a given binary and input file, check the file type of the input file
3. Spawn a fuzzer based on the input file type,
4. Run the fuzzer on the example input as a seed, and use mutation strategy from seed to generate random inputs
5. Record the crash in `fuzzer_output/` directory

### File Type Check

Source: `file_type_check.py`

This python module checks the file type of an input when paired with the given binary . It checks whether the input files is either:

- CSV
- JSON
- JPEG
- ELF
- PDF
- XML

If the input file does not match any of the above signatures and structures, then it is considered a Plaintext file

### Mechanism

1. Use magic number to determine JPEG, ELF, PDF
2. Use parser to check if it is CSV or JSON
3. Otherwise, we fall back to Plaintext

## Fuzzer

Source: `fuzzer.py`

Fuzzer uses a **mutation**-based strategy to generate malformed/randomised output from valid seeds (input file) to cause crashes or abnormal behavior in target binaries.

Framework is modular:

- The function `run_binary()` handles the binary execution
- crash detection, and logging,
- Different functions implement different mutator strategies which are chained together to produce randomise malformed output to the target binary

### Mechanism

1. Seed input: Read valid seed files from `example_inputs/` directory.

2. Mutation policy: For each iteration, apply 1 to 6 randomly selected mutators (via composition), such as structural corruption, encoding-boundary stress, random byte insertion, truncation, pattern repetition, and deep nesting.

3. Execution model: Feed mutated inputs to the target binary (via file or stdin) using subprocess.run with a 1-second timeout.

4. Crash definition: A run is recorded as a crash if the process times out or exits with a negative return code (terminated by signal). Logged data include exit code, signal, stdout, stderr, and the seed/mutation trace.

5. Artifact preservation: On crash, write the responsible input to `fuzzer_output/bad_{progname}.txt` to satisfy evaluation interfaces and enable deterministic replay.

### capabilities

### Plaintext

For plaintext, the strategy is tightly aligned to the three binaries' semantics, using a round-robin of three specialised payload families instead of generic mutation:

More precisely, we focussed on

- format strings
- using a dictionary of predefined attacks
- password and id input pairs
- Non-numeric or exotic tokens: NaN, inf, 1e309, random ASCII blobs.

### JSON:

The JSON fuzzer systematically attacks grammar validity, nesting depth, numeric and Unicode edge cases, and token repetition, while preserving enough structure that most inputs still resemble JSON.

Our strategy focusses on grammatically incorrect input and encoding.

Mutations:

- unbalanced braces
- duplicate keys
- broken escapes
- illegal Unicode
- extreme nesting
- oversized strings.

### CSV:

The CSV fuzzer focuses on line-oriented parsers, field length boundaries, and encoding edge cases in a relatively simple grammar. We focus on length / overflow pressure and structural corruption; to target line splitting and field parsing edge cases, integer/length issues, encoding/UTF-8 handling bugs, and poor handling of high-volume repeated records.

Mutations:

- inconsistent columns
- unusual delimiters
- long UTF-8 sequences
- repeated patterns
- random byte insertions
- truncations.

### XML

For XML, the core idea is to drive depth/width limits and entity/attribute expansion, while also exploring malformed constructs and potential downstream format-string issues. Targeting depth-based overflow/stack errors, entity/attribute expansion, malformed tag handling, character referencing, and secondary format-string issues.

- increase nesting
- create large nodes
- inject tokens
- inject format strings

### PDF

Since the PDF file structure is considered a graph of different file formats, we fuzz different metadata including:

- Title
- Subject
- PDF version
- Shuffling pages
- Rotating pages
- Adding multiple or one pages
- Page deletion
- Adjusting stream (binary data length)
- Injecting junk attributes

These are considered the base metadata that PDF parses analyse for. However, more specific and targeted PDF’s that discover vulnerabilities typically target internal file formats such as JPEG, JIBG2 compression or TTF.

Thus, the following addition to mutations include:

- Corrupting the font descriptor length in TTF
- Bit flipping the font stream
- Truncating or extending the font stream
- Tampering the MaxProfile Table in TTF

Not only so, there are various JPEG file format standards such as JPX (JPEG 2000), JBIG2, JBIG3, supported that are considered vulnerable by past CVE’s due to buffer overflows, etc. Mutations include:

- Corrupting the JPX, JIBG2 headers
- Mutating the dimensions
- Or binary streams via performing bit flips

Lastly, mutating the XREF headers in PDF was the cause of several CVE’s such as CVE-2022-27135, because of heap overflows from excessive reads, etc. Mutations that we implemented include:

- Corrupting the startxref
- Mutating the XREF table
- Mutating the XREF stream

### ELF

For ELF, the strategy is to keep the ELF magic valid while systematically corrupting header fields that drive loader logic. We target malformed header-driven OOB reads/writes, mis-computed loops over headers, and loader logic that assumes “reasonable” offsets, counts, and sizes. Magic bytes are always restored.

Header mutations:

- `e_phoff, e_shoff` (program/section header offsets),
- `e_phnum, e_shnum` (entry counts),
- `e_ehsize, e_phentsize, e_shentsize` (entry sizes),
- `e_flags`

And more generic mutations:

- sparse random byte flips
- inject random blobs after the ELF header.
- delete chunks from the body, preserves the first 0x40 bytes.

### JPEG

The JPEG fuzzer aims to corrupt the header information, jpegs are split into many segments, these segments are delimited by markers, which denote either metadata, data, or both. We target parsing errors in the jpeg standard.

Mainly targeting integer the parsing of segments, and integer overflows in their fields.

- SOF marker height over flow underflow and underflow, and randomisation
- randomise number of components (these are allocated on the heap in nanojpeg, and mishandlings would cause memory leaks)
- marker corruption, change a random marker to a possibly invalid one

The JPEG fuzzer is not currently functional, and in future we should focus on more compression bugs

## Harness

The harness went through two iterations, the first one gets called by the main fuzzer program directly as a subprocess, the second was spawned as a server and would handle multiple binaries at the same time. The harness simply hooks into the binary with ptrace and captures signals. It can produce a stack trace that provides offsets into each binary and library loaded into the address space.

The simpler version just redirects the stdin from Python into the stdin of the process to test, and acts as a simple wrapper to catch signals. By inspecting memory mappings in procfs and the program headers of the ELF binary we can de-ASLR the stack trace and get a hash of this trace to identify a unique crash.

We worked on a multithreaded implementation, where the Python process would send instructions over IPC and provide a pipe. Waiting for ptrace events and spawning processes would be performed in different threads. The thought here is that it would reduce the setup time of spawning a new harness process however the overhead of creating the pipe in Python and passing that down to the binary proved to be large enough to not be worth it. The design of passing the mutated data down to the binary needed to be reconsidered.

## Vulnerable binaries

To improve our fuzzer during development, we wrote some extra vulnerable
binaries. These binaries can be found in `src/vulnerable-binaries`. We will
now briefly summarise what is the intended functionalities of these binaries
and why they are vulnerable:

### display-csv

Binary: `src/vulnerable-binaries/display-csv`
Source: `src/vulnerable-binaries/display-csv.c`

This binary parses a given CSV as [s-expression](https://en.wikipedia.org/wiki/S-expression)
and display it.

For example, running

```
$ ./src/vulnerable-binaries/display-csv <./example_inputs/csv1.txt
```

results in the output

```
((header must stay intact) (a b c S) (e f g ecr) (i j k et))
```

#### Vulnerabilities

The second line is vulnerable because `line` returned by `getline` is
not guaranteed to be string of length > 0. This is an array out of bound error.

```
int r = getline(&line, &len, stdin);
line[strlen(line) - 1] = '\0'; // VULN: array out of bound
```

The first `printf` call suffers from format string injection. As a value in the
CSV, `ls->first` is a user-controlled string that can contain format specifier.

```
static void display_string_list_recur(list *ls)
{
  if (ls)
    {
      printf((char *)(ls->first)); // VULN: format string

      if (ls->rest)
        printf(" ");

      display_string_list_recur(ls->rest);
    }
}
```

### display-json

Binary: `src/vulnerable-binaries/display-json`
Source: `src/vulnerable-binaries/display-json.c`

This binary parses a given JSON as [s-expression](https://en.wikipedia.org/wiki/S-expression)
and display it.

For example, running

```
$ ./src/vulnerable-binaries/display-json <./example_inputs/json1.txt
```

results in the output

```
(("len" 12) ("input" "AAAABBBBCCCC") ("more_data" ("a" "bb")))
```

#### Vulnerabilities

The second line suffers from integer overflow because `c` is a user-controlled
character. An attacker can include an integer > INT64_MAX in JSON to trigger
this integer overflow.

```
int64_t d = c - 0x30;
return read_number_recur(acc * 10 + d); // VULN: integer overflow
```

In the following, there is neither validation on whether `new_buf_size` overflow
nor `realloc` succeed. In a memory constraint system, an attacker would be able
to force `new_buf_size` to overflow and `realloc` to fail, in order to force
subsequent `read_string_recur` calls to write to invalid memory.

```
ungetc(c, stdin);
size_t new_buf_size = buf_size * 2; // VULN: integer overflow
char *new_buf = realloc(buf, new_buf_size);
return read_string_recur(new_buf, new_buf_size, j);
```

## Future improvements

- Fileio is currently our largest speed bottleneck
  - a scheduler to run the fuzzer on multiple threads may alleviate this, the design could be modified to read the seed file once, and copy the bytes across multiple instances (or pass it in read only maybe)
  - a lock would be needed for the crash reporting file
  - could use threads, check python 3.14 spec if GIL is disabled by default.

- Improving JPEG fuzzing capability, jpeg currently doesn’t effectively crash binaries, with more time and a bit more debugging we could improve
  - would also be interesting to corrupt compression metadata
  - and inject possibly unsupported segments from newer standards.
