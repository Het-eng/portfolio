

import argparse
import socket
import re
import os
from datetime import datetime

# ══════════════════════════════════════════════
#  NETWORK PROBE (Port Scanner)
# ══════════════════════════════════════════════
def network_probe(target, port_from, port_to):
    print(f"\n[PROBE] Target: {target} | Range: {port_from}-{port_to}")
    print("-" * 50)
    found = []
    for p in range(port_from, port_to + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((target, p)) == 0:
                try:
                    svc = socket.getservbyport(p)
                except:
                    svc = "unknown"
                print(f"  OPEN  {p:5}  [{svc}]")
                found.append(p)
            s.close()
        except KeyboardInterrupt:
            print("\n[!] Probe stopped by user.")
            break
    total = len(found)
    print("-" * 50)
    print(f"[PROBE] Done. {total} open port(s) detected.\n")


# ══════════════════════════════════════════════
#  CREDENTIAL AUDITOR (Password Strength)
# ══════════════════════════════════════════════
def audit_credential(pwd):
    print(f"\n[AUDIT] Evaluating credential...\n")
    rules = [
        ("Min 12 characters",          len(pwd) >= 12),
        ("Contains uppercase (A-Z)",   bool(re.search(r'[A-Z]', pwd))),
        ("Contains lowercase (a-z)",   bool(re.search(r'[a-z]', pwd))),
        ("Contains number (0-9)",      bool(re.search(r'[0-9]', pwd))),
        ("Contains symbol (!@#...)",   bool(re.search(r'[\W_]', pwd))),
        ("Avoids weak patterns",       not bool(re.search(
            r'(pass|1234|abc|admin|login|welcome)', pwd, re.IGNORECASE))),
    ]
    passed = 0
    for rule, ok in rules:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}]  {rule}")
        if ok:
            passed += 1

    rating = {6: "EXCELLENT", 5: "STRONG", 4: "AVERAGE"}.get(passed, "POOR")
    print(f"\n  Result : {passed}/6 rules passed")
    print(f"  Rating : {rating}\n")


# ══════════════════════════════════════════════
#  SYSTEM LOG INSPECTOR
# ══════════════════════════════════════════════
def inspect_log(log_path):
    print(f"\n[INSPECT] Reading: {log_path}\n")
    re_fail    = re.compile(r'Failed password for (\S+) from ([\d.]+)')
    re_success = re.compile(r'Accepted password for (\S+) from ([\d.]+)')

    logins, failures, attacker_map = [], [], {}

    try:
        with open(log_path) as fh:
            for line in fh:
                m1 = re_fail.search(line)
                m2 = re_success.search(line)
                if m1:
                    failures.append((m1.group(1), m1.group(2)))
                    attacker_map[m1.group(2)] = attacker_map.get(m1.group(2), 0) + 1
                if m2:
                    logins.append((m2.group(1), m2.group(2)))
    except FileNotFoundError:
        print(f"  [ERR] File not found: {log_path}\n")
        return

    print(f"  Successful Logins  : {len(logins)}")
    for u, ip in logins[:5]:
        print(f"    -> {u} from {ip}")

    print(f"\n  Failed Attempts    : {len(failures)}")
    print(f"  Unique Attacker IPs: {len(attacker_map)}")
    print()
    for ip, cnt in sorted(attacker_map.items(), key=lambda x: -x[1])[:8]:
        warn = "  <<< THREAT DETECTED" if cnt >= 5 else ""
        print(f"    {ip:<18} {cnt} attempt(s){warn}")
    print()


# ══════════════════════════════════════════════
#  ACCESS CONTROL MANAGER (Firewall)
# ══════════════════════════════════════════════
def manage_access(deny_ip, permit_ports, save_path=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rules = [
        "#!/bin/bash",
        f"# Cyber Guard — Access Control Rules | Generated: {ts}",
        "",
        "# Reset all chains",
        "iptables -F && iptables -X",
        "",
        f"# === DENY: {deny_ip} ===",
        f"iptables -I INPUT  -s {deny_ip} -j DROP",
        f"iptables -I OUTPUT -d {deny_ip} -j DROP",
        "",
        "# === PERMIT PORTS ===",
    ]
    for pt in permit_ports:
        rules.append(f"iptables -A INPUT  -p tcp --dport {pt} -j ACCEPT")
        rules.append(f"iptables -A OUTPUT -p tcp --sport {pt} -j ACCEPT")

    rules += ["", "# Default policy", "iptables -P INPUT DROP",
              "iptables -P FORWARD DROP", "iptables -P OUTPUT ACCEPT",
              "", "echo '[+] Access control rules applied successfully.'"]

    content = "\n".join(rules)
    if save_path:
        with open(save_path, "w") as fh:
            fh.write(content)
        print(f"\n[ACM] Rules saved to: {save_path}\n")
    else:
        print("\n" + content + "\n")


# ══════════════════════════════════════════════
#  SHOWCASE (Demo)
# ══════════════════════════════════════════════
def showcase():
    print("\n" + "═" * 55)
    print("       CYBER GUARD — FEATURE SHOWCASE")
    print("═" * 55)

    print("\n>>> [1] NETWORK PROBE — localhost ports 20-100")
    network_probe("127.0.0.1", 20, 100)

    print("\n>>> [2] CREDENTIAL AUDIT")
    audit_credential("S3cur3P@ssw0rd#99")

    print("\n>>> [3] ACCESS CONTROL RULES")
    manage_access("10.0.0.99", [22, 8080, 443])


# ══════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════
def main():
    cli = argparse.ArgumentParser(
        prog="cyber_guard.py",
        description="Cyber Guard — Network Probe | Credential Auditor | Log Inspector | Access Control"
    )
    sub = cli.add_subparsers(dest="cmd")

    # probe
    pr = sub.add_parser("probe", help="Scan open ports on a target host")
    pr.add_argument("target")
    pr.add_argument("--from", dest="port_from", type=int, default=1)
    pr.add_argument("--to",   dest="port_to",   type=int, default=1024)

    # audit
    au = sub.add_parser("audit", help="Evaluate password strength")
    au.add_argument("credential")

    # inspect
    ins = sub.add_parser("inspect", help="Analyse system auth log")
    ins.add_argument("logfile")

    # acm
    ac = sub.add_parser("acm", help="Generate firewall/access control rules")
    ac.add_argument("--deny",   required=True)
    ac.add_argument("--permit", nargs="+", type=int, default=[])
    ac.add_argument("--save",   default=None)

    # showcase
    sub.add_parser("showcase", help="Run full feature demonstration")

    args = cli.parse_args()

    if   args.cmd == "probe":    network_probe(args.target, args.port_from, args.port_to)
    elif args.cmd == "audit":    audit_credential(args.credential)
    elif args.cmd == "inspect":  inspect_log(args.logfile)
    elif args.cmd == "acm":      manage_access(args.deny, args.permit, args.save)
    elif args.cmd == "showcase": showcase()
    else: cli.print_help()

if __name__ == "__main__":
    main()
