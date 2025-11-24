"""
Helper script for Wireshark integration
Provides commands and utilities for capturing network traffic with Wireshark/tcpdump
"""

import subprocess
import sys
import os
from datetime import datetime


def capture_with_tcpdump(interface: str = None, output_file: str = None, duration: int = None):
    """
    Start tcpdump capture (alternative to Wireshark GUI)
    
    Args:
        interface: Network interface (e.g., 'en0', 'eth0'). Use None to auto-detect
        output_file: Output pcap file path
        duration: Capture duration in seconds (None = until stopped)
    """
    if output_file is None:
        output_file = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    
    # Auto-detect interface if not provided
    if interface is None:
        try:
            result = subprocess.run(['route', 'get', 'default'], 
                                  capture_output=True, text=True)
            # Try to extract interface (macOS specific)
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    interface = line.split(':')[1].strip()
                    break
        except:
            interface = 'en0'  # Default for macOS
    
    cmd = ['sudo', 'tcpdump', '-i', interface, '-w', output_file]
    
    if duration:
        cmd.extend(['-G', str(duration), '-W', '1'])
    
    print(f"Starting tcpdump capture...")
    print(f"Interface: {interface}")
    print(f"Output: {output_file}")
    print(f"Press Ctrl+C to stop")
    print(f"\nCommand: {' '.join(cmd)}")
    print("\nTo run manually:")
    print(f"  {' '.join(cmd)}")
    
    return cmd


def get_wireshark_commands():
    """Print instructions for using Wireshark"""
    print("=" * 60)
    print("WIRESHARK CAPTURE INSTRUCTIONS")
    print("=" * 60)
    print("\n1. INSTALL WIRESHARK:")
    print("   macOS: brew install wireshark")
    print("   Linux: sudo apt-get install wireshark")
    print("\n2. START CAPTURE:")
    print("   - Open Wireshark")
    print("   - Select network interface (usually 'en0' on macOS, 'eth0' on Linux)")
    print("   - Click 'Start capturing packets'")
    print("\n3. FILTER SETTINGS:")
    print("   - Filter for HTTP: http")
    print("   - Filter for localhost: host 127.0.0.1")
    print("   - Filter for specific port: tcp.port == 8080")
    print("   - Exclude localhost: !(host 127.0.0.1)")
    print("\n4. SAVE CAPTURE:")
    print("   - File -> Save As")
    print("   - Choose .pcap format")
    print("\n5. ANALYZE:")
    print("   - Statistics -> Protocol Hierarchy")
    print("   - Statistics -> Conversations")
    print("   - Export HTTP objects")
    print("=" * 60)


def capture_during_benchmark(output_file: str = None):
    """
    Instructions for capturing during benchmark run
    """
    if output_file is None:
        output_file = f"benchmark_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    
    print("=" * 60)
    print("CAPTURING TRAFFIC DURING BENCHMARK")
    print("=" * 60)
    print("\nOption 1: Wireshark GUI")
    print("  1. Start Wireshark before running benchmark")
    print("  2. Select interface and start capture")
    print("  3. Run: python llm_web_agent/benchmark.py")
    print("  4. Stop capture after benchmark completes")
    print("  5. Save as:", output_file)
    
    print("\nOption 2: tcpdump (command line)")
    interface = 'en0'  # Adjust for your system
    cmd = capture_with_tcpdump(interface, output_file)
    print(f"\n  Terminal 1: {' '.join(cmd)}")
    print(f"  Terminal 2: python llm_web_agent/benchmark.py")
    print(f"  Stop tcpdump after benchmark (Ctrl+C)")
    
    print("\nOption 3: Python + tcpdump (automated)")
    print("  Use the capture_with_tcpdump() function")
    print("=" * 60)


def analyze_pcap_basic(pcap_file: str):
    """
    Basic analysis commands for pcap file
    """
    print("=" * 60)
    print(f"ANALYZING PCAP: {pcap_file}")
    print("=" * 60)
    
    commands = [
        ("Count HTTP requests", f"tshark -r {pcap_file} -Y http -T fields -e http.request.method | wc -l"),
        ("List unique domains", f"tshark -r {pcap_file} -Y http -T fields -e http.host | sort -u"),
        ("Show all HTTP requests", f"tshark -r {pcap_file} -Y http -T fields -e http.request.method -e http.request.uri"),
        ("Count packets to external IPs", f"tshark -r {pcap_file} -Y 'ip.dst != 127.0.0.1' -T fields -e ip.dst | sort -u | wc -l"),
        ("Export HTTP objects", f"tshark -r {pcap_file} --export-objects http,./http_objects/"),
    ]
    
    print("\nUseful tshark commands (if installed):")
    for desc, cmd in commands:
        print(f"\n{desc}:")
        print(f"  {cmd}")
    
    print("\nOr open in Wireshark GUI:")
    print(f"  wireshark {pcap_file}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "commands":
            get_wireshark_commands()
        elif sys.argv[1] == "capture":
            capture_during_benchmark()
        elif sys.argv[1] == "analyze" and len(sys.argv) > 2:
            analyze_pcap_basic(sys.argv[2])
        else:
            print("Usage:")
            print("  python wireshark_helper.py commands  # Show Wireshark instructions")
            print("  python wireshark_helper.py capture    # Show capture instructions")
            print("  python wireshark_helper.py analyze <file.pcap>  # Analyze pcap")
    else:
        get_wireshark_commands()
        print("\n")
        capture_during_benchmark()


