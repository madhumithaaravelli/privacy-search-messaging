#!/bin/bash

# Script to run benchmark with Wireshark/tcpdump capture
# This captures ALL network traffic during the benchmark

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="capture_benchmark_${TIMESTAMP}.pcap"
INTERFACE="en0"  # Change to your network interface (use 'ip link' or 'ifconfig' to find)

echo "=========================================="
echo "BENCHMARK WITH NETWORK CAPTURE"
echo "=========================================="
echo ""
echo "This will:"
echo "  1. Start tcpdump to capture network traffic"
echo "  2. Run the benchmark script"
echo "  3. Stop capture when done"
echo ""
echo "Output files:"
echo "  - PCAP: ${PCAP_FILE}"
echo "  - Python logs: traffic_log_local_*.jsonl"
echo "  - Results: benchmark_results.json"
echo ""
read -p "Press Enter to start (or Ctrl+C to cancel)..."

# Check if tcpdump is available
if ! command -v tcpdump &> /dev/null; then
    echo "ERROR: tcpdump not found. Install it:"
    echo "  macOS: brew install tcpdump"
    echo "  Linux: sudo apt-get install tcpdump"
    exit 1
fi

# Detect interface if not set
if [ "$INTERFACE" = "en0" ]; then
    # Try to auto-detect (macOS)
    DETECTED=$(route get default 2>/dev/null | grep interface | awk '{print $2}')
    if [ -n "$DETECTED" ]; then
        INTERFACE="$DETECTED"
    fi
fi

echo "Using interface: $INTERFACE"
echo "Starting tcpdump in background..."

# Start tcpdump in background
sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" &
TCPDUMP_PID=$!

# Wait a moment for tcpdump to start
sleep 2

echo "tcpdump started (PID: $TCPDUMP_PID)"
echo "Starting benchmark..."
echo ""

# Run benchmark
cd "$(dirname "$0")/.."
source path/to/venv/bin/activate
python llm_web_agent/benchmark.py

# Stop tcpdump
echo ""
echo "Stopping tcpdump..."
sudo kill $TCPDUMP_PID
wait $TCPDUMP_PID 2>/dev/null

echo ""
echo "=========================================="
echo "CAPTURE COMPLETE"
echo "=========================================="
echo "PCAP file: $PCAP_FILE"
echo ""
echo "To analyze:"
echo "  wireshark $PCAP_FILE"
echo "  or"
echo "  python llm_web_agent/wireshark_helper.py analyze $PCAP_FILE"
echo ""


