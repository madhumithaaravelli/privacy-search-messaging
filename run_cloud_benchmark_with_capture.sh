#!/bin/bash

# Script to run cloud benchmark with Wireshark/tcpdump capture
# Usage: ./run_cloud_benchmark_with_capture.sh <service> [options]

if [ $# -lt 1 ]; then
    echo "Usage: $0 <service> [benchmark_options]"
    echo ""
    echo "Services:"
    echo "  google  - Google Custom Search API"
    echo "  openai  - OpenAI API (ChatGPT)"
    echo ""
    echo "Example:"
    echo "  $0 google --api-key YOUR_KEY --cx SEARCH_ENGINE_ID"
    echo "  $0 openai --api-key YOUR_KEY"
    echo ""
    echo "Or set environment variables:"
    echo "  export GOOGLE_API_KEY=..."
    echo "  export GOOGLE_CX=..."
    echo "  export OPENAI_API_KEY=..."
    exit 1
fi

SERVICE=$1
shift  # Remove service from args, pass rest to benchmark script

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="capture_cloud_${SERVICE}_${TIMESTAMP}.pcap"
INTERFACE="en0"  # Change to your network interface

echo "=========================================="
echo "CLOUD BENCHMARK WITH NETWORK CAPTURE"
echo "=========================================="
echo ""
echo "Service: $SERVICE"
echo "This will:"
echo "  1. Start tcpdump to capture network traffic"
echo "  2. Run the cloud benchmark script"
echo "  3. Stop capture when done"
echo ""
echo "Output files:"
echo "  - PCAP: ${PCAP_FILE}"
echo "  - Python logs: traffic_log_cloud_${SERVICE}_*.jsonl"
echo "  - Results: benchmark_results_cloud_${SERVICE}_*.json"
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
echo "Starting cloud benchmark..."
echo ""

# Run cloud benchmark
cd "$(dirname "$0")/.."
source path/to/venv/bin/activate
python llm_web_agent/cloud_benchmark.py "$SERVICE" "$@"

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


