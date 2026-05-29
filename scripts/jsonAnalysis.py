import json
import glob
import argparse
from collections import defaultdict, Counter
from datetime import datetime
import sys
import statistics
import requests
import os

# Helper to parse timestamps
def parse_time(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
    except Exception as e:
        return None

# Get geolocation and ISP info for an IP address using MaxMind
GEO_CACHE_FILE = "ip_geo_cache.json"
def load_geo_cache():
    if os.path.exists(GEO_CACHE_FILE):
        try:
            with open(GEO_CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_geo_cache(cache):
    try:
        with open(GEO_CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print("[!] Failed to save geolocation cache.", e)

def get_ip_info(ip, cache):
    import geoip2.database
    GEOIP_CITY_DB = os.getenv("MAXMIND_CITY_DB", "GeoLite2-City.mmdb")
    GEOIP_ASN_DB = os.getenv("MAXMIND_ASN_DB", "GeoLite2-ASN.mmdb")

    if ip in cache:
        return cache[ip]

    try:
        with geoip2.database.Reader(GEOIP_CITY_DB) as city_reader:
            with geoip2.database.Reader(GEOIP_ASN_DB) as asn_reader:
                city = city_reader.city(ip)
                asn = asn_reader.asn(ip)

                result = {
                    "ip": ip,
                    "city": city.city.name,
                    "region": city.subdivisions.most_specific.name,
                    "country": city.country.name,
                    "org": asn.autonomous_system_organization or "",
                    "asn": asn.autonomous_system_number,
                    "loc": f"{city.location.latitude},{city.location.longitude}"
                }
                cache[ip] = result
                return result
    except Exception as e:
        cache[ip] = {"ip": ip, "error": f"lookup failed: {str(e)}"}
        return cache[ip]

def interpret_tcp_flags(flags):
    if not flags:
        flags = ""
    def flag_set(f):
        return set(f.replace("*", ""))
    interpretations = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }
    anomalies = []
    desc = []
    if flags:
        for ch in flags:
            if ch in interpretations:
                desc.append(interpretations[ch])
    desc_str = ", ".join(desc)

    if "S" in flags and "A" in flags and len(flags.strip("*")) == 2:
        anomalies.append("[!] SYN-ACK seen without prior SYN from this source - possible spoof or unsolicited reply")
    elif "F" in flags and "S" in flags:
        anomalies.append("[!] FIN and SYN both set - invalid combination, often used in scans")
    elif "R" in flags and "S" in flags:
        anomalies.append("[!] RST and SYN both set - suspicious")
    elif len(flags.strip("*")) == 0:
        anomalies.append("[!] No control flags set - may be malformed or crafted packet")

        # Detect scan types based on flags
    flag_combo = flag_set(flags)
    if flag_combo == {"S"}:
        anomalies.append("[!] Possible SYN scan")
    elif flag_combo == {"F"}:
        anomalies.append("[!] Possible FIN scan")
    elif flag_combo == {"F", "P", "U"}:
        anomalies.append("[!] Possible XMAS scan")
    elif not flag_combo:
        anomalies.append("[!] Possible NULL scan")
    elif flag_combo == {"A"}:
        anomalies.append("[!] Possible ACK scan")
    elif flag_combo == {"R"}:
        anomalies.append("[!] Possible RST scan")
    elif flag_combo == {"S", "A"}:
        anomalies.append("[!] Possible response to SYN scan")
    return desc_str, anomalies

KNOWN_SCANNER_KEYWORDS = ["Censys", "Shodan", "Shadowserver", "Rapid7", "Project Sonar", "NetSystemsResearch", "BinaryEdge"]

def analyze_logs(log_entries):
    all_timestamps = [parse_time(entry.get("packet_time")) for entry in log_entries if parse_time(entry.get("packet_time"))]
    if all_timestamps:
        start_time = min(all_timestamps)
        end_time = max(all_timestamps)
        print(f"=== Honeypot Log Time Range: {start_time} to {end_time} ===")
    source_ips = Counter()
    dest_ports = Counter()
    sequences = defaultdict(list)
    timestamps_by_ip = defaultdict(list)
    sessions = defaultdict(list)

    for entry in log_entries:
        ts = parse_time(entry.get("packet_time"))
        src_ip = entry.get("src_ip")
        dst_ip = entry.get("dst_ip")
        src_port = entry.get("src_port")
        dst_port = entry.get("dst_port")
        flags = entry.get("flags")

        if not (ts and src_ip and dst_ip and src_port and dst_port):
            continue

        try:
            dst_port = int(dst_port)
        except ValueError:
            continue

        session_key = (src_ip, dst_ip, src_port, dst_port)
        sessions[session_key].append((ts, flags))

        source_ips[src_ip] += 1
        dest_ports[dst_port] += 1
        sequences[src_ip].append((ts, dst_port, flags))
        timestamps_by_ip[src_ip].append(ts)

    print("--- Source IP Address Patterns ---")
    benign_scanners = []
    ip_info_cache = load_geo_cache()

    for ip, count in source_ips.most_common():
        print(f"{ip}: {count} events")
        info = get_ip_info(ip, ip_info_cache)
        org = info.get("org") or ""
        if any(scanner.lower() in org.lower() for scanner in KNOWN_SCANNER_KEYWORDS):
            benign_scanners.append((ip, org))

    top_ip, top_ip_count = source_ips.most_common(1)[0]
    if top_ip_count > 3:
        print(f"\n[!] High activity detected from {top_ip}. May indicate automated scanning or targeted attack.")

    print("--- Destination Port Patterns ---")
    port_ip_map = defaultdict(set)
    for entry in log_entries:
        dst_port = entry.get("dst_port")
        src_ip = entry.get("src_ip")
        if dst_port and src_ip:
            try:
                port = int(dst_port)
                port_ip_map[port].add(src_ip)
            except ValueError:
                continue
    for port, count in dest_ports.most_common():
                print(f"Port {port}: {count} hits from {len(port_ip_map[port])} unique IPs")
    top_port, top_port_count = dest_ports.most_common(1)[0]
    if top_port_count > 3:
        print(f"[!] Port {top_port} is being targeted frequently. Could indicate a service-specific attack.")

    print("--- Destination Port Focus by Unique IPs ---")
    sorted_by_uniqueness = sorted(port_ip_map.items(), key=lambda x: len(x[1]), reverse=True)
    for port, ip_set in sorted_by_uniqueness[:10]:
        print(f"Port {port}: {len(ip_set)} unique IPs targeting this port")

    print("--- Correlation Across TCP Sessions ---")
    for session, events in sessions.items():
        src_ip, dst_ip, src_port, dst_port = session
        events.sort()
        flags_sequence = []
        anomalies_detected = []

        for ts, flags in events:
            desc, anomalies = interpret_tcp_flags(flags or "")
            flags_sequence.append((ts, flags, desc, anomalies))
            anomalies_detected.extend(anomalies)

        if flags_sequence and flags_sequence[0][1] and ("S" not in flags_sequence[0][1] or any("R" in (f[1] or "") for f in flags_sequence) or anomalies_detected):
            print(f"Session {src_ip}:{src_port} -> {dst_ip}:{dst_port}:")
            for ts, flags, desc, anomalies in flags_sequence:
                print(f"  {ts.isoformat()} - Flags: {flags} ({desc})")
                for anomaly in anomalies:
                    print(f"    {anomaly}")
            if flags_sequence[0][1] and "S" not in flags_sequence[0][1]:
                print("  [!] Session initiated without SYN flag - unusual or crafted connection attempt")
            if [f[1] for f in flags_sequence].count("R") > 2:
                print("  [!] Multiple RSTs detected - possible scanning or reset attack")

    print("--- Attack Sequencing and TCP Flag Analysis ---")
    for ip, events in sequences.items():
        events.sort()
        print(f"\n{ip} sequence:")
        for ts, port, flags in events:
            desc, anomalies = interpret_tcp_flags(flags or "")
            print(f"  {ts.isoformat()} -> port {port}, flags: {flags} ({desc})")
            for anomaly in anomalies:
                print(f"    {anomaly}")
        if len(events) > 3:
            print(f"  [!] {len(events)} events from {ip}. Review for potential brute-force or enumeration attempts.")

    print("\n--- Timing and Jitter Analysis ---")
    hour_counts = Counter()
    weekday_counts = Counter()
    month_counts = Counter()
    work_hours_counts = Counter()

    for ip, ts_list in timestamps_by_ip.items():
        ts_list.sort()
        for ts in ts_list:
            hour_counts[ts.hour] += 1
            info = get_ip_info(ip, ip_info_cache)
            loc = info.get("loc")
            tz_offset = 0
            try:
                if loc:
                    import timezonefinder, pytz
                    from datetime import timezone
                    lat, lon = map(float, loc.split(","))
                    tf = timezonefinder.TimezoneFinder()
                    tz_str = tf.timezone_at(lat=lat, lng=lon)
                    if tz_str:
                        local_tz = pytz.timezone(tz_str)
                        local_dt = ts.replace(tzinfo=timezone.utc).astimezone(local_tz)
                        if 8 <= local_dt.hour <= 17:
                            work_hours_counts[ip] += 1
            except Exception:
                pass
            weekday_counts[ts.strftime('%A')] += 1
            month_counts[ts.strftime('%B')] += 1
            
        deltas = [(ts_list[i+1] - ts_list[i]).total_seconds() for i in range(len(ts_list)-1)]
        if deltas:
            mean_delta = statistics.mean(deltas)
            jitter = statistics.stdev(deltas) if len(deltas) > 1 else 0
            print(f"{ip}: mean delta = {mean_delta:.2f}s, jitter = {jitter:.2f}s, events = {len(ts_list)}")
            if mean_delta < 1.0 and jitter < 0.5:
                print(f"  [!] Low mean delta and jitter may indicate scripted or automated probing from {ip}.")

    print("\n--- Hour of Day Distribution ---")
    for hour in range(24):
        print(f"{hour:02d}:00 - {hour_counts[hour]} events")

    print("\n--- Day of Week Distribution ---")
    for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
        print(f"{day}: {weekday_counts[day]} events")

    print("\n--- Month of Year Distribution ---")
    for month in ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]:
        if month_counts[month]:
            print(f"{month}: {month_counts[month]} events")

    print("\n--- Workday Hour Anomalies ---")
    for ip, count in work_hours_counts.items():
        if len(timestamps_by_ip[ip]) > 0 and count / len(timestamps_by_ip[ip]) > 0.8:
            print(f"{ip}: {count} events during workday hours (possible business automation or targeted probing)")

    print("\n--- Source IP Geolocation and ISP Info ---")
    for ip in list(source_ips.keys())[:10]:
        info = get_ip_info(ip, ip_info_cache)
        if "error" in info:
            print(f"{ip}: lookup failed")
        else:
            print(f"{ip}: {info.get('city')}, {info.get('region')}, {info.get('country')} - ASN{info.get('asn')} {info.get('org')}")
    save_geo_cache(ip_info_cache)

    countries = Counter([info.get("country") for info in ip_info_cache.values() if info.get("country")])
    print("--- Source Country Clustering ---")
    for country, count in sorted(countries.items(), key=lambda item: item[1], reverse=True):
        print(f"{country}: {count} IPs")
    if len(countries) > 3:
        print("[!] Attacks appear distributed across multiple countries.")

    print("\n--- Known Benign Internet Scanners ---")
    for ip, org in benign_scanners:
        print(f"{ip} identified as {org} (likely benign scanning)")

    print("\n--- Summary of Security Insights ---")
    print(f"Total unique source IPs: {len(source_ips)}")
    print(f"Total unique destination ports targeted: {len(dest_ports)}")
    if len(source_ips) > 10:
        print("[!] High number of unique source IPs. Potentially a distributed scan or botnet activity.")
    if len(dest_ports) > 10:
        print("[!] Broad port range targeted. Indicates port scanning behavior.")

def read_logs(files):
    entries = []
    for file in files:
        try:
            with open(file) as f:
                for line in f:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print(f"File not found: {file}")
    return entries

def read_stdin():
    entries = []
    for line in sys.stdin:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries

def main():
    parser = argparse.ArgumentParser(description="Analyze honeypot event logs for anomalies and attack patterns.")
    parser.add_argument('files', nargs='*', help="Log files or wildcards (e.g., logs/*.json). If empty, reads from stdin.")
    args = parser.parse_args()

    if args.files:
        files = []
        for pattern in args.files:
            files.extend(glob.glob(pattern))
        logs = read_logs(files)
    else:
        logs = read_stdin()

    if not logs:
        print("No valid logs to process.")
        return

    analyze_logs(logs)

if __name__ == "__main__":
    main()
