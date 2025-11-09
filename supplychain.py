#!/usr/bin/env python3

import os
import pkg_resources
import requests
import hashlib
import json
from datetime import datetime

OSV_URL = "https://api.osv.dev/v1/query"
PYPI_URL = "https://pypi.org/pypi/{}/json"

report = {
    "generated_at": str(datetime.utcnow()),
    "packages": []
}

def compute_local_hash(pkg):
    try:
        location = pkg.location
        package_file = os.path.join(location, pkg.project_name.replace("-", "_"))
        if os.path.isdir(package_file):
            hasher = hashlib.sha256()
            for root, _, files in os.walk(package_file):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, "rb") as fh:
                            hasher.update(fh.read())
                    except:
                        pass
            return hasher.hexdigest()
    except:
        return None
    return None

def fetch_pypi_hash(name, version):
    try:
        response = requests.get(PYPI_URL.format(name))
        data = response.json()
        files = data.get("releases", {}).get(version, [])
        for f in files:
            if f.get("digests", {}).get("sha256"):
                return f["digests"]["sha256"]
    except:
        pass
    return None

def check_vulnerabilities(name, version):
    query = {"package": {"name": name, "version": version, "ecosystem": "PyPI"}}
    r = requests.post(OSV_URL, json=query).json()
    if "vulns" in r:
        return [{"id": v["id"], "summary": v.get("summary", "No description")} for v in r["vulns"]]
    return []

def analyze():
    print("\n=== SUPPLY CHAIN SECURITY SCANNER ===\n")

    for dist in pkg_resources.working_set:
        name = dist.project_name
        version = dist.version

        print(f"📦 Package: {name} ({version})")

        local_hash = compute_local_hash(dist)
        pypi_hash = fetch_pypi_hash(name, version)

        tampered = (local_hash != pypi_hash) if (local_hash and pypi_hash) else None

        if local_hash:
            print(f"   🔹 Local Hash: {local_hash}")
        if pypi_hash:
            print(f"   🔹 PyPI Official Hash: {pypi_hash}")

        if tampered is True:
            print(f"   ❗ TAMPERING DETECTED — Hash mismatch")
        elif tampered is False:
            print(f"   ✅ No tampering detected")
        else:
            print(f"   ⚠ Unable to verify tampering")

        vulns = check_vulnerabilities(name, version)

        if vulns:
            print(f"   ❗ Vulnerabilities Found:")
            for v in vulns:
                print(f"       - {v['id']}: {v['summary']}")
        else:
            print(f"   ✅ No known vulnerabilities in OSV database")

        report["packages"].append({
            "name": name,
            "version": version,
            "local_hash": local_hash,
            "pypi_hash": pypi_hash,
            "tampered": tampered,
            "vulnerabilities": vulns
        })

        print()

    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("✅ Scan Complete. Report saved as report.json\n")

if __name__ == "__main__":
    analyze()
