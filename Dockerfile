# Start from a default ubuntu image.
FROM ubuntu:22.04

# Copy/Compile my fuzzer
COPY fuzzer /
RUN chmod +x /fuzzer

# Run it.
CMD ["/bin/bash", "/fuzzer"]

