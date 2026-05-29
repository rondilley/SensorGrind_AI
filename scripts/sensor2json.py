import sys
import glob
import json
import re
import fileinput

def parse_log_line(line):
    try:
        header, msg = line.split("sensor: ", 1)
    except ValueError:
        return None

    parts = header.strip().split()
    if len(parts) < 4:
        return None

    data = {
        "log_time": " ".join(parts[0:3]),
        "sensor_ip": parts[3],
        "hostname": parts[4],
    }

    tokens = msg.strip().split()
    idx = 0

    # Handle PacketTime (with date and time)
    if tokens[idx].startswith("PacketTime:"):
        packet_time_value = tokens[idx].split(":", 1)[1]
        if idx + 1 < len(tokens) and re.match(r"^\d{2}:\d{2}:\d{2}\.\d+", tokens[idx + 1]):
            packet_time_value += " " + tokens[idx + 1]
            idx += 1
        data["packet_time"] = packet_time_value
        idx += 1

    while idx < len(tokens):
        token = tokens[idx]

        if re.match(r'^IPv4/\S+', token):
            data["proto"] = token
            idx += 1
            if idx + 2 < len(tokens) and tokens[idx + 1] == "->":
                try:
                    src_ip, src_port = tokens[idx].split(":")
                    dst_ip, dst_port = tokens[idx + 2].split(":")
                    data["src_ip"] = src_ip
                    data["src_port"] = src_port
                    data["dst_ip"] = dst_ip
                    data["dst_port"] = dst_port
                    idx += 3
                    continue
                except ValueError:
                    pass

        if ':' in token:
            key, val = token.split(':', 1)
            data[key.lower()] = val
        else:
            if "flags" not in data:
                data["flags"] = token
            else:
                data["extra"] = data.get("extra", "") + " " + token

        idx += 1

    return data

def process_input(sources):
    for line in fileinput.input(files=sources if sources else ('-',)):
        line = line.strip()
        if line:
            parsed = parse_log_line(line)
            if parsed:
                print(json.dumps(parsed))

if __name__ == "__main__":
    file_patterns = sys.argv[1:]
    expanded_files = []

    for pattern in file_patterns:
        expanded_files.extend(glob.glob(pattern))

    process_input(expanded_files)