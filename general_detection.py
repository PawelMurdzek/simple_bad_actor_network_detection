import pyshark
from scapy.all import rdpcap, Packet, TCP, IP, UDP, Raw, wrpcap # wrpcap added for dummy file creation during testing. Remove if not needed.
import os
import re
from scapy.all import conf, rdpcap
import subprocess
import collections
import numpy as np
import math

# Set Tshark path for Pyshark
# You'll need to ensure this path is correct for your system
# conf.prog.tshark = r"C:\Program Files\Wireshark\tshark.exe" # Example path, adjust as needed
# In your provided code, you set it inside analyze_pcap_file, moving it here for global effect.
try:
    # Attempt to find tshark in common locations or assume it's in PATH
    subprocess.check_output(['tshark', '-v'])
    conf.prog.tshark = 'tshark' # Assume it's in PATH
except (subprocess.CalledProcessError, FileNotFoundError):
    # Fallback to a common installation path on Windows
    if os.name == 'nt': # Windows
        possible_tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        if os.path.exists(possible_tshark_path):
            conf.prog.tshark = possible_tshark_path
        else:
            print("Warning: tshark not found in PATH or at C:\\Program Files\\Wireshark\\tshark.exe.")
            print("Please ensure Wireshark is installed and tshark is in your system's PATH, or update conf.prog.tshark manually.")
            # sys.exit(1) # Uncomment to exit if tshark is critical
    else: # Linux/macOS
        print("Warning: tshark not found in PATH. Please ensure Wireshark is installed and tshark is in your system's PATH.")
        # sys.exit(1) # Uncomment to exit if tshark is critical

print(f"Current conf.prog.tshark after setting: {conf.prog.tshark}")

# --- Configuration ---
# Base directory for your pcap files
# Ensure these directories exist and contain your pcap files
BASE_PCAP_DIR = 'P1/' # Assuming 'hidden_data' and 'fake_data' are directly under the script's location

# Paths to your hidden and fake data pcap files
HIDDEN_DATA_DIR = os.path.join(BASE_PCAP_DIR, 'hidden_data')
FAKE_DATA_DIR = os.path.join(BASE_PCAP_DIR, 'fake_data')

# Load the Antygona text for potential pattern matching (if applicable)
ANTYGONA_TEXT_FILE = 'Sofokles-Antygona.txt' # Path to the Antygona text file

antygona_content = ""
try:
    with open(ANTYGONA_TEXT_FILE, 'r', encoding='cp1250') as f:
        antygona_content = f.read()
except FileNotFoundError:
    print(f"Error: {ANTYGONA_TEXT_FILE} not found. Please ensure the Antygona text file is in the correct directory.")
    # You might want to exit or handle this more gracefully if the text is critical for your detection.
    # For now, we'll continue, but some detection methods might be less effective.


# --- Helper Functions for Specific Detection Techniques ---

def calculate_entropy(data):
    """Calculate the Shannon entropy of a byte string."""
    if not data:
        return 0.0
    byte_counts = collections.Counter(data)
    total_bytes = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * np.log2(probability)
    return entropy

def analyze_packet_length_steg(packets):
    """
    Detects if hidden data is encoded in subtle variations of packet lengths.
    Looks for non-standard deviations in packet lengths, especially odd/even distributions.
    """
    lengths = [len(p) for p in packets if p.haslayer(IP)]
    if not lengths:
        return False, "No IP packets for length analysis."

    # Statistical analysis of packet lengths
    mean_len = np.mean(lengths)
    std_dev_len = np.std(lengths)

    # Look for a higher-than-usual proportion of odd or even packet lengths
    # This can indicate LSB embedding in length fields or slight modifications.
    odd_lengths = sum(1 for l in lengths if l % 2 != 0)
    even_lengths = sum(1 for l in lengths if l % 2 == 0)

    # If one parity significantly outweighs the other, it might be suspicious.
    # Thresholds here are empirical and might need tuning.
    if len(lengths) > 50: # Only apply if enough packets for statistical relevance
        if odd_lengths / len(lengths) > 0.65 or even_lengths / len(lengths) > 0.65:
            return True, f"Unusual packet length parity distribution (odd:{odd_lengths}, even:{even_lengths})"

    # Look for small, consistent deviations from typical lengths
    # This is more complex and might require a baseline. For now, look for very small, non-standard lengths.
    # Example: If most packets are 1514, but some are 1515, it could be LSB.
    # We'd need to group by common sizes and then check deviations.
    return False, "No significant length anomalies."

def analyze_tcp_timestamp_steg(packets):
    """
    Detects if hidden data is encoded in TCP timestamps.
    Looks for non-sequential or unusual patterns in timestamp values.
    """
    timestamps = []
    for pkt in packets:
        if TCP in pkt and pkt[TCP].options:
            for opt in pkt[TCP].options:
                if opt[0] == 'Timestamp':
                    timestamps.append(opt[1][0]) # TSval
    if not timestamps:
        return False, "No TCP timestamps found."

    # Look for unusual variance or non-sequential jumps
    # If timestamps are normally incremental, look for large jumps or non-monotonic sequences.
    if len(timestamps) > 1:
        diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if any(d < 0 for d in diffs):
            return True, "Non-monotonic TCP timestamp sequence detected." # Timestamps should generally increase
        
        mean_diff = np.mean(diffs)
        std_diff = np.std(diffs)
        
        # If std_diff is very high compared to mean_diff, it could indicate randomness
        if mean_diff > 0 and std_diff / mean_diff > 0.5: # Arbitrary threshold
             return True, f"High variance in TCP timestamp differences (mean_diff:{mean_diff:.2f}, std_diff:{std_diff:.2f})"

    # A more advanced check would involve looking for LSB in timestamps.
    # For instance, if the LSB of timestamps frequently follows a specific pattern.
    lsb_counts = collections.Counter(ts & 1 for ts in timestamps)
    if len(lsb_counts) == 2 and (lsb_counts[0] / len(timestamps) > 0.65 or lsb_counts[1] / len(timestamps) > 0.65):
        return True, "Unusual LSB distribution in TCP timestamps."

    return False, "No significant TCP timestamp anomalies."


def analyze_ip_id_field_steg(packets):
    """
    Detects if hidden data is encoded in the IP Identification field.
    The IP ID field is typically incremented sequentially or pseudo-randomly.
    Steganography often introduces non-sequential or predictable patterns.
    """
    ip_ids = [p[IP].id for p in packets if IP in p]
    if not ip_ids:
        return False, "No IP packets for ID analysis."

    # Check for non-sequential or unusually predictable patterns
    # A simple check: look for many identical IDs or IDs that are very low/high consistently
    id_counts = collections.Counter(ip_ids)
    for id_val, count in id_counts.items():
        if count > len(ip_ids) * 0.1 and id_val != 0: # More than 10% of packets have the same non-zero ID
            return True, f"High frequency of repeated IP ID: {id_val} ({count} occurrences)."

    # Look for perfect sequentiality in a subset of packets that shouldn't be (e.g., across different flows)
    # This is hard without flow tracking.
    
    # Check for LSB patterns in IP IDs
    lsb_counts = collections.Counter(ip_id & 1 for ip_id in ip_ids)
    if len(lsb_counts) == 2 and (lsb_counts[0] / len(ip_ids) > 0.65 or lsb_counts[1] / len(ip_ids) > 0.65):
        return True, "Unusual LSB distribution in IP IDs."

    return False, "No significant IP ID field anomalies."

def analyze_payload_steg(packet, antygona_content):
    """
    Analyzes the payload for steganography.
    Improved: Checks for entropy, common character patterns, and byte distribution anomalies.
    """
    if Raw in packet and packet[Raw].load:
        payload_bytes = packet[Raw].load
        
        # 1. Entropy analysis: High or very low entropy can be suspicious.
        # Hidden data might normalize entropy, or make it excessively random.
        entropy = calculate_entropy(payload_bytes)
        # Assuming typical network traffic has an entropy range; deviations are suspicious.
        # This requires a baseline, but for now, look for extreme values.
        # A typical text payload might have entropy around 4-6 bits/byte. Encrypted/stego might be 7-8.
        if entropy > 7.0: # Very high entropy, possibly encrypted or compressed stego
            return True, f"High payload entropy detected ({entropy:.2f} bits/byte)."
        if entropy < 2.0 and len(payload_bytes) > 50: # Very low entropy for a substantial payload
            return True, f"Very low payload entropy detected ({entropy:.2f} bits/byte)."

        # 2. Byte frequency analysis: Look for unusual byte distributions.
        # Steganography can alter the natural frequency distribution of bytes.
        byte_counts = collections.Counter(payload_bytes)
        # If certain bytes are excessively frequent or rare compared to typical English text/binary data.
        # This is a complex statistical test, but a simple check is to look for a highly skewed distribution.
        if byte_counts:
            most_common_byte, most_common_count = byte_counts.most_common(1)[0]
            if most_common_count / len(payload_bytes) > 0.30: # More than 30% of payload is one byte
                return True, f"Dominant byte (0x{most_common_byte:02x}) in payload ({most_common_count / len(payload_bytes):.2%} of payload)."

        # 3. Direct string search (if Antygona content is used as a known pattern)
        # This is generally weak for sophisticated stego but included for completeness.
        if antygona_content:
            try:
                payload_str = payload_bytes.decode('cp1250', errors='ignore') # Use the same encoding as Antygona text
                # Search for specific, less common phrases or unique character sequences from Antygona
                # Instead of "Antygona" or "Sofokles", which are too obvious.
                # Example: look for "Nikt nad prawem nie ma władzy tak wielkiej," (a phrase from Antygona)
                # This needs careful selection of specific phrases that are unlikely to appear naturally.
                if "władzy tak wielkiej" in payload_str or "prawa są odwieczne" in payload_str:
                    return True, "Specific Antygona phrase found in payload (highly suspicious)."
            except Exception:
                pass # Decoding errors are common with arbitrary payloads

    return False, "No significant payload anomalies."


def calculate_entropy(data):
    """Calculate the Shannon entropy of a byte string."""
    if not data:
        return 0.0
    byte_counts = collections.Counter(data)
    total_bytes = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        # Handle cases where probability is 0 to avoid log(0)
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy

def analyze_protocol_specific_fields(pyshark_packet):
    """
    Analyzes specific protocol fields for anomalies, using Pyshark's dissection.
    Now with more detailed DNS steganography checks.
    """
    stego_indicators = [] # Collect all indicators found for this packet

    # --- HTTP Headers (retained from previous version) ---
    if hasattr(pyshark_packet, 'http'):
        try:
            user_agent = pyshark_packet.http.user_agent
            if user_agent:
                if len(user_agent) > 256:
                    stego_indicators.append(f"Unusually long HTTP User-Agent ({len(user_agent)} chars).")
                alphanum_count = sum(c.isalnum() for c in user_agent)
                if len(user_agent) > 0 and (alphanum_count / len(user_agent) < 0.7):
                    stego_indicators.append("HTTP User-Agent contains unusually high proportion of non-alphanumeric characters.")
            
            if hasattr(pyshark_packet.http, 'referer'):
                referer = pyshark_packet.http.referer
                if referer and (len(referer) > 512 or re.search(r'[^a-zA-Z0-9\s\.\-_/:?&=]', referer)):
                    stego_indicators.append("Suspicious HTTP Referer header detected.")
            
            if hasattr(pyshark_packet.http, 'request_method') and pyshark_packet.http.request_method not in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']:
                stego_indicators.append(f"Unusual HTTP request method: {pyshark_packet.http.request_method}")
            
            if hasattr(pyshark_packet.http, 'request_uri') and len(pyshark_packet.http.request_uri) > 512:
                stego_indicators.append("Excessively long HTTP URI path.")

        except AttributeError:
            pass

    # --- Enhanced DNS Queries/Responses Analysis ---
    if hasattr(pyshark_packet, 'dns'):
        try:
            # 1. DNS Query Name (QNAME) Analysis
            if hasattr(pyshark_packet.dns, 'qry_name'):
                query_name = pyshark_packet.dns.qry_name
                
                # Strip trailing dot if present (common in DNS)
                if query_name.endswith('.'):
                    query_name = query_name[:-1]

                # Max legitimate FQDN length is 255 bytes, but individual labels are max 63.
                # A very long qry_name overall can indicate tunneling.
                if len(query_name) > 63: # Individual label limit, a common tunneling indicator
                    stego_indicators.append(f"Unusually long DNS query name (QNAME): '{query_name}' ({len(query_name)} chars). Potential DNS tunneling.")

                # Analyze parts of the domain name (labels) for randomness/entropy
                labels = query_name.split('.')
                for label in labels:
                    if len(label) > 4: # Only analyze labels with sufficient length
                        label_entropy = calculate_entropy(label.encode('utf-8', errors='ignore'))
                        # High entropy in a label can indicate encoded data (e.g., DGA or stego)
                        if label_entropy > 4.5: # Threshold for high entropy (tune this)
                            stego_indicators.append(f"High entropy in DNS label '{label}' (Entropy: {label_entropy:.2f}).")
                        
                        # Look for low complexity (e.g., repetitive characters like 'aaaaa.example.com')
                        if len(label) > 10 and len(set(label)) / len(label) < 0.2: # Tune thresholds
                            stego_indicators.append(f"Low character diversity (high repetition) in DNS label '{label}'.")

                        # Check for unusual character sets (e.g., base64 or hex characters often used for encoding)
                        # This is a very basic check, you could use regex for more specific patterns.
                        if re.search(r'[^a-zA-Z0-9\-_]', label): # Non-standard characters
                             # Exclude common special chars if you expect them in legitimate names
                             if not re.search(r'^[a-zA-Z0-9\-_.]+$', label): # If it contains anything beyond common DNS chars
                                 stego_indicators.append(f"Unusual characters in DNS label: '{label}'.")

            # 2. DNS Record Type Analysis (e.g., excessive TXT or NULL records)
            # This requires looking at the response, or the query if you know the type being asked for.
            # Pyshark's 'qr' field indicates query (0) or response (1).
            if pyshark_packet.dns.qr == '1' and hasattr(pyshark_packet.dns, 'rr_type'): # It's a response and has a record type
                rr_type = pyshark_packet.dns.rr_type
                # Common types are A (1), AAAA (28), CNAME (5), NS (2), MX (15), PTR (12)
                # TXT (16) and NULL (10) are often abused.
                if rr_type == '16': # TXT record
                    # Check the data in the TXT record for high entropy or suspicious content
                    if hasattr(pyshark_packet.dns, 'txt'):
                        txt_data = pyshark_packet.dns.txt.replace(':', '').replace('.', '') # Clean up for analysis
                        if len(txt_data) > 0:
                            txt_entropy = calculate_entropy(txt_data.encode('utf-8', errors='ignore'))
                            if txt_entropy > 4.5: # High entropy in TXT record data
                                stego_indicators.append(f"High entropy in DNS TXT record data (Entropy: {txt_entropy:.2f}). Potential encoded data.")
                            if len(txt_data) > 128: # Unusually long TXT record data
                                stego_indicators.append(f"Unusually long DNS TXT record data ({len(txt_data)} chars).")
                elif rr_type == '10': # NULL record
                    stego_indicators.append(f"DNS NULL record detected (type {rr_type}). Often abused for steganography.")

            # 3. DNS Transaction ID (ID) analysis
            # While less common for direct stego, subtle changes might occur.
            # ID is usually random for security. Deviations could be suspicious.
            if hasattr(pyshark_packet.dns, 'id'):
                dns_id = int(pyshark_packet.dns.id, 16) # Convert hex string to int
                # Check LSB for even/odd distribution or specific patterns if you suspect.
                # Requires tracking across multiple packets to be meaningful, similar to IP ID.
                # For a single packet, it's hard to tell without context.

        except AttributeError:
            pass # Field not present or parsing error

    return len(stego_indicators) > 0, stego_indicators # Return True if any indicators found, and the list of indicators

# --- Main Analysis Function ---

def analyze_pcap_file(pcap_path, is_stego_expected=False):
    """
    Analyzes a single .pcap file for signs of network steganography.
    """
    print(f"\n--- Analyzing file: {os.path.basename(pcap_path)} (Stego expected: {is_stego_expected}) ---")

    potential_stego_indicators = []
    
    try:
        # Pyshark for high-level dissection and access to raw packet bytes
        cap_pyshark = pyshark.FileCapture(pcap_path)
        
        # Load all Scapy packets once for efficiency in Scapy-specific analyses
        # For very large files, this might consume a lot of memory.
        # An alternative is to convert pyshark_packet.raw_packet.get_bytes() to Scapy packet inside the loop.
        # But for statistical analysis across packets, loading all is better.
        try:
            scapy_packets = rdpcap(pcap_path)
        except Exception as e:
            print(f"Warning: Could not read pcap with Scapy for statistical analysis: {e}")
            scapy_packets = []

        # Perform statistical analysis across *all* packets if needed
        # These functions now take the list of scapy_packets
        detected_len, msg_len = analyze_packet_length_steg(scapy_packets)
        if detected_len:
            potential_stego_indicators.append(f"Packet length anomaly detected: {msg_len}")
        
        detected_ts, msg_ts = analyze_tcp_timestamp_steg(scapy_packets)
        if detected_ts:
            potential_stego_indicators.append(f"TCP timestamp anomaly detected: {msg_ts}")
        
        detected_ipid, msg_ipid = analyze_ip_id_field_steg(scapy_packets)
        if detected_ipid:
            potential_stego_indicators.append(f"IP ID field anomaly detected: {msg_ipid}")


        packet_count = 0
        for pyshark_packet in cap_pyshark:
            packet_count += 1
            
            # Protocol-specific field analysis (using Pyshark)
            detected_proto, msg_proto = analyze_protocol_specific_fields(pyshark_packet)
            if detected_proto:
                potential_stego_indicators.append(f"Protocol-specific anomaly in packet {packet_count}: {msg_proto}")

            # Payload analysis (requires raw bytes, can convert to Scapy packet if needed)
            # Pyshark's raw_packet.get_bytes() is efficient here.
            try:
                # Reconstruct Scapy packet from Pyshark raw bytes for payload analysis
                # This might fail for non-IP packets or malformed ones.
                scapy_packet_from_pyshark = IP(pyshark_packet.raw_packet.get_bytes())
                detected_payload, msg_payload = analyze_payload_steg(scapy_packet_from_pyshark, antygona_content)
                if detected_payload:
                    potential_stego_indicators.append(f"Payload anomaly in packet {packet_count}: {msg_payload}")
            except Exception:
                pass # Could not parse raw packet bytes into Scapy IP packet

        cap_pyshark.close()

        if potential_stego_indicators:
            print(f"Potential steganography indicators found in {os.path.basename(pcap_path)}:")
            # Use set to avoid duplicates from multiple checks on the same phenomenon, then sort
            for indicator in sorted(list(set(potential_stego_indicators))):
                print(f"  - {indicator}")
            return True, potential_stego_indicators
        else:
            print(f"No obvious steganography indicators found in {os.path.basename(pcap_path)}.")
            return False, []

    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        return False, []

# --- Main Script Execution ---

if __name__ == "__main__":
    pcap_files_to_process = []

    # Process hidden_data files (expected to contain stego)
    if os.path.exists(HIDDEN_DATA_DIR):
        for i in range(1, 8): # part1.pcap to part7.pcap
            file_name = f'part{i}.pcap'
            full_path = os.path.join(HIDDEN_DATA_DIR, file_name)
            if os.path.exists(full_path):
                pcap_files_to_process.append({'path': full_path, 'is_stego': True})
            else:
                print(f"Warning: {full_path} not found. Skipping.")
    else:
        print(f"Warning: Directory {HIDDEN_DATA_DIR} not found. No hidden data files to process.")

    # Process fake_data files (expected to be clean)
    if os.path.exists(FAKE_DATA_DIR):
        for i in range(1, 8): # part1.pcap to part7.pcap
            file_name = f'part{i}.pcap'
            full_path = os.path.join(FAKE_DATA_DIR, file_name)
            if os.path.exists(full_path):
                pcap_files_to_process.append({'path': full_path, 'is_stego': False})
            else:
                print(f"Warning: {full_path} not found. Skipping.")
    else:
        print(f"Warning: Directory {FAKE_DATA_DIR} not found. No fake data files to process.")

    if not pcap_files_to_process:
        print("No .pcap files found to process. Please ensure 'hidden_data' and 'fake_data' directories exist and contain .pcap files.")

    # --- Perform Analysis ---
    detection_results = {}
    for pcap_info in pcap_files_to_process:
        path = pcap_info['path']
        is_stego = pcap_info['is_stego']
        detected, indicators = analyze_pcap_file(path, is_stego)
        detection_results[os.path.basename(path)] = {
            'expected_stego': is_stego,
            'detected_by_us': detected,
            'indicators': indicators
        }

    print("\n\n--- Summary of Analysis Results ---")
    for filename, result in detection_results.items():
        print(f"File: {filename}")
        print(f"  Expected Stego: {result['expected_stego']}")
        print(f"  Detected by Our Script: {result['detected_by_us']}")
        if result['indicators']:
            print(f"  Indicators Found:")
            for ind in result['indicators']:
                print(f"    - {ind}")
        else:
            print(f"  No specific indicators found by our script.")
        print("-" * 30)

    # --- How to Present Findings in Your Documentation ---
    print("\n\n--- Table for Documentation (Example) ---")
    print("| Metoda/Grupa projektująca | Domniemana zasada działania (zwięźle) | Zastosowany sposób detekcji |")
    print("| :------------------------ | :------------------------------------- | :-------------------------- |")

    # This part is highly dependent on your actual findings for each red team.
    # You'll deduce the "Metoda/Grupa projektująca" (e.g., "Grupa A - FTP Timestamp Stego")
    # and the "Domniemana zasada działania" (e.g., "Ukrywanie danych w najmniej znaczących bitach pola TCP Timestamp")
    # from your analysis.
    # You will fill this table after you run the script against the actual pcap files
    # and manually verify the findings or perform deeper analysis.
    # For example:
    # print("| Red Team A (hidden_data/partX.pcap) | Data encoded in TCP Window Size (LSB) | Custom Scapy script, statistical analysis of window sizes |")
    # print("| Red Team B (hidden_data/partY.pcap) | Data in HTTP User-Agent header (padding) | Pyshark analysis for unusual User-Agent lengths |")