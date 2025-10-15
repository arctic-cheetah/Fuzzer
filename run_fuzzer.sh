#!/bin/bash

# Ensure the binaries folder exists.
if [ ! -d "binaries" ]; then
    echo "Error: No folder named binaries exists in CWD."
    exit 1
fi
# Ensure the example_inputs folder exists.
if [ ! -d "example_inputs" ]; then
    echo "Error: No folder named example_inputs exists in CWD."
    exit 1
fi

# Make a folder for fuzzer_output
if [ ! -d "fuzzer_output" ]; then
    echo "Creating fuzzer_output folder"
    mkdir fuzzer_output
fi

echo "Deleting old fuzzer output files."
rm 'fuzzer_output/*' 2>/dev/null

echo "Docker container building..."
docker build -t fuzzer-image .
if [ $? -ne 0 ]; then
    echo "Error: Failed to build docker container"
    exit 1
fi
echo "Docker container built successfully"

# Run the image, mounting /binaries as read-only and /fuzzer_output
echo "Running Fuzzer"
docker run -v ./binaries:/binaries:ro -v ./example_inputs:/example_inputs:ro -v ./fuzzer_output:/fuzzer_output fuzzer-image
