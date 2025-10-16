# Start from a default ubuntu image.
FROM debian:bookworm-slim

# Copy/Compile my fuzzer
COPY fuzzer /
RUN chmod +x /fuzzer

# Run it.
CMD ["/bin/bash", "/fuzzer"]

