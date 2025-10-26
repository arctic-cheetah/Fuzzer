#/bin/bash

echo "My Awesome Fuzzer"

cat /example_inputs/challenge1.txt | /binaries/challenge1 &2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Example input crashed binary??"
    exit 1
fi

echo "AAAAAAAAAAAAAAAAAAAAA" | /binaries/challenge1
if [ $? -eq 0 ]; then
    echo "Error: Couldn't crash binary??"
    exit 1
fi

echo "I found a hack!. Writing to /fuzzer_output/challenge1.txt"
echo "AAAAAAAAAAAAAAAAAAAAA" > /fuzzer_output/challenge1.txt
exit 0
