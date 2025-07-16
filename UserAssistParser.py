from tqdm import tqdm
import csv
import math
import os
import subprocess
import winreg
import codecs
from pathlib import Path
def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)
    except:
        return None
def is_signed(file_path):
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             f"Get-AuthenticodeSignature '{file_path}' | Select-Object -ExpandProperty Status"],
            capture_output=True, text=True)
        return "Valid" in result.stdout
    except:
        return False
def parse_userassist_keys():
    results = []
    decoded_entries = []

    base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path) as ua_base:
            for i in range(winreg.QueryInfoKey(ua_base)[0]):
                guid = winreg.EnumKey(ua_base, i)
                count_path = f"{base_path}\\{guid}\\Count"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as count_key:
                        for j in range(winreg.QueryInfoKey(count_key)[1]):
                            name, _, _ = winreg.EnumValue(count_key, j)
                            try:
                                decoded = codecs.decode(name, 'rot_13')
                                if decoded.lower().endswith(('.exe', '.lnk')):
                                    decoded_entries.append(decoded)
                            except:
                                continue
                except FileNotFoundError:
                    continue
    except FileNotFoundError:
        return []
    for decoded in tqdm(decoded_entries, desc="Analyzing UserAssist entries", unit="entry"):
        exists = os.path.isfile(decoded)
        entropy = calculate_entropy(decoded) if exists else None
        signed = is_signed(decoded) if exists else None

        results.append({
            'Name': os.path.basename(decoded),
            'Full Path': decoded,
            'Exists': exists,
            'Entropy': entropy,
            'Signed': signed
        })

    return results
def save_to_csv(data, output_file='userassist_report.csv'):
    if data:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        print(f"[+] Report saved to: {output_file}")
    else:
        print("[-] No valid UserAssist entries found.")
if __name__ == "__main__":
    print("[*] Parsing UserAssist keys...")
    data = parse_userassist_keys()
    save_to_csv(data)
