import os
import argparse
import hashlib
import yara
import requests
import json
from dotenv import load_dotenv

# Load environment variables from a .env file (if present)
load_dotenv()

# Retrieve the VirusTotal API key from environment variables
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH')

if not VIRUSTOTAL_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")


def scan_file_with_yara(file_path):
    '''
    Scans the file against the yara rule provided.
    :param file_path: path to yara rules
    '''
    rules = yara.compile(filepath=YARA_RULES_PATH)
    matches = rules.match(file_path)
    return matches


def get_file_hash(file_path,algorithm = "sha256"):
    '''
    Returns the hash of the file.
    :param file_path: path to the file to be hashed.
    :param algorithm: hashing algortihm to be used. (Default: sha256)
    '''
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception("Incompatible Hashing Algorithm (Valid Algorithms: sha256 | sha1 | md5)")
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hasher.update(byte_block) # Hashing each block of size 4096 bytes
    return hasher.hexdigest()


def check_hash_with_virustotal(file_hash):
    '''
    Checks the file hash against the VirusTotal Malicious sample hash database.
    :param file_hash: hash of the file to be checked.
    '''
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def scan_file(file_path,hash_algorithm):
    '''
    Scans the file against YARA rules and VirusTotal Database.
    :param file_path: path to the file to be scanned.
    :param hash_algorithm: hash algorithm to be used.
    '''
    print(f"Scanning file: {file_path}")
    
    # # YARA Scan
    # print("YARA Scan:\n")
    # yara_matches = scan_file_with_yara(file_path)
    # if yara_matches:
    #     print(f"YARA detected potential threats: {yara_matches}")
    # else:
    #     print("No threats detected by YARA.")
    
    # VirusTotal Scan
    print("VirusTotal Scan:\n")
    file_hash = get_file_hash(file_path,hash_algorithm)
    vt_result = check_hash_with_virustotal(file_hash)
    if vt_result:
        print(f"VirusTotal scan result: {json.dumps(vt_result, indent=2)}")
    else:
        print("File not found in VirusTotal database or API limit reached.")


def scan_directory(directory_path,hash_algorithm):
    '''
    Scans the directory recursively.
    :param directory_path: path to the directory to scan.
    :param hash_algorithm: hasing algorithm to be used.
    '''
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path,hash_algorithm)


def main():
    parser = argparse.ArgumentParser(description="AegisShield - Malware Detection Program")
    parser.add_argument("-d","--directory", help="Specify the directory to scan.")
    parser.add_argument("-f","--file", help="Specify a single file to scan.")
    parser.add_argument("-h","--hash",help="Specify the hash algorithm to use (md5, sha256, sha1)",default="sha256")
    
    args = parser.parse_args()
    
    if args.directory:
        scan_directory(args.directory,args.hash)
    elif args.file:
        scan_file(args.file,args.hash)
    else:
        print("Please specify a directory or a file to scan.")

if __name__ == "__main__":
    main()
