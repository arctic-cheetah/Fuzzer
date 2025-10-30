
b_insert
random_bytes
is_crash
mutators
run_binary
long_string
control_chars
break_quotes
trailing_commas
unbalanced_braces
duplicate_keys
deep_nesting
numeric_edgecases
random_block
shuffle_array_items
break_unicode
delete_random_block
repeat_token



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
If the input file does not match any of the above signatures and structures, then it is considered a text file (TXT)

### Mechanism:
- Use magic number to determine JPEG, ELF, PDF
- Use parser to check CSV or JSON
- ELSE txt

## 4) Harness:
``` hanress.cpp``` An incomplete implementation used to obtain code coverage and run the binary. It is currently deployed in ```fuzzer.py```
