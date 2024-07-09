import os
import argparse
import hashlib
import yara
import requests
from alive_progress import alive_bar
from dotenv import load_dotenv

# Load environment variables from a .env file (if present)
load_dotenv()

# Retrieve the VirusTotal API key from environment variables
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH')  # Path to your YARA rules file

if not VIRUSTOTAL_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")


def scan_file_with_yara(file_path):
    """
    Scan a file with YARA rules.
    Parameters:
    :param file_path (str): The path to the file to scan.
    :param rules (yara.Rules): The YARA rules to use for scanning.
    Returns:
    list: A list of matches found by YARA.
    """
    rules = yara.compile(filepath=YARA_RULES_PATH)
    matches = rules.match(file_path)
    return matches

def get_file_hash(file_path):
    """
    Get the SHA256 hash of a file.

    Parameters:
    :param file_path (str): The path to the file.

    Returns:
    str: The SHA256 hash of the file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_hash_with_virustotal(file_hash):
    """
    Check a file hash against the VirusTotal database.

    Parameters:
    :param file_hash (str): The SHA256 hash of the file.

    Returns:
    dict: The response from the VirusTotal API.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 204:
        print('Request rate limit exceeded. You are making more requests than allowed.')
        exit(0)
    elif response.status_code == 400:
        print("Bad request. Your request was somehow incorrect.")
        exit(0)
    elif response.status_code == 403:
        print("Forbidden. You don't have enough privileges to make the request.")
        exit(0)
    else:
        return {}

def analyze_virustotal_report(report):
    """
    Analyze the response from VirusTotal and print statistics.

    Parameters:
    :param response (dict): The response from the VirusTotal API.
    """
    if not report or "data" not in report:
        print("No data available from VirusTotal.")
        return
    
    attributes = report["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    print("VirusTotal Report Statistics:")
    print(f"  Harmless: {stats.get('harmless', 0)}")
    print(f"  Malicious: {stats.get('malicious', 0)}")
    print(f"  Suspicious: {stats.get('suspicious', 0)}")
    print(f"  Undetected: {stats.get('undetected', 0)}")


def scan_file(file_path):
    """
    Scan a single file with YARA rules and VirusTotal.

    Parameters:
    :param file_path: The path to the fiel to be scanned
    """
    print(f"Scanning file: {file_path}")
    
    # YARA Scan
    print("\nYARA Scan:")
    yara_matches = scan_file_with_yara(file_path)
    if yara_matches:
        print(f"  YARA detected potential threats: {yara_matches}")
    else:
        print("  No threats detected by YARA.")
    
    # VirusTotal Scan
    print("\nVirusTotal Scan:")
    file_hash = get_file_hash(file_path)
    vt_result = check_hash_with_virustotal(file_hash)
    if vt_result:
        analyze_virustotal_report(vt_result)
    else:
        print("  File not found in VirusTotal database(Probably Benign)")
    
    print("-"*100)

def scan_directory(directory):
    """
    Scan a directory of files with YARA rules and VirusTotal.

    Parameters:
    :param directory (str): The path to the directory to scan.
    """
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    results = []

    with alive_bar(len(files), title='Scanning Files') as bar:
        for file in files:
            matches = scan_file_with_yara(file)
            file_hash = get_file_hash(file)
            vt_response = check_hash_with_virustotal(file_hash)
            
            result = f"File: {file}\n"
            result += "\nYARA Scan:\n"
            if matches:
                result += f"  YARA detected potential threats: {matches}\n"
            else:
                result += "  No threats detected by YARA.\n"
            
            result += "\nVirusTotal Scan:\n"
            if vt_response is {} :
                result += "  File not found in VirusTotal database (Probably Benign)\n"
            else:
                stats = vt_response.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                result += "VirusTotal Report Statistics:\n"
                result += f"  Harmless: {stats.get('harmless', 0)}\n"
                result += f"  Malicious: {stats.get('malicious', 0)}\n"
                result += f"  Suspicious: {stats.get('suspicious', 0)}\n"
                result += f"  Undetected: {stats.get('undetected', 0)}\n"
                if stats.get('malicious', 0) > 0:
                    result += "Result: This file is malicious.\n"
                else:
                    result += "Result: This file is not malicious.\n"
            
            result += "-"*100
            results.append(result)
            bar()
    print()
    for result in results:
        print(result)

def print_ascii_art():
    with open("./Assets/ascii-text-art.txt", 'r') as file:
        art = file.read()
    print(art)


def main():
    print_ascii_art()
    parser = argparse.ArgumentParser(description="AegisShield Malware Detection Program")
    parser.add_argument("-d","--directory", help="Specify the directory to scan.")
    parser.add_argument("-f","--file", help="Specify a single file to scan.")
    
    args = parser.parse_args()
    
    if args.directory:
        scan_directory(args.directory)
    elif args.file:
        scan_file(args.file)
    else:
        print("Please specify a directory or a file to scan.")

if __name__ == "__main__":
    main()
