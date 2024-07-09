# AegisShield : The Malware Detection Program

**Author:** Hem Sagar \
**Date:** June 27, 2024

## Table of Contents
1. [Introduction](#1-introduction)
2. [Project Overview](#2-project-overview)
3. [Features](#3-features)
4. [Installation](#4-installation)
5. [Usage](#5-usage)
6. [Testing](#6-testing)
7. [Limitations](#7-limitations)
8. [Future Enhancements](#8-future-enhancements)
9. [References](#9-references)

## 1. Introduction

**Purpose:** The Malware Detection Program is designed to scan files and directories for malware infections using signature-based detection and VirusTotal API integration.

**Scope:** This project focuses on detecting known malware signatures and providing detailed reports. It does not cover heuristic or behavior-based detection.

## 2. Project Overview

**Objective:** To create a tool that can scan files for known malware signatures and check file hashes against the VirusTotal database.

**Tools and Technologies:** Python, YARA, VirusTotal API, ClamAV.

**System Architecture:**
- File selection module
- Hashing and signature comparison
- VirusTotal API integration
- Output generation

## 3. Features

- Scans files for known malware signatures using YARA rules.
- Checks file hashes against the VirusTotal database.
- Generates detailed scan reports.

## 4. Installation

**Prerequisites:**
- Python 3.x
- Required Python libraries (listed in `requirements.txt`)

**Step-by-Step Installation Guide:**
1. Clone the repository:
   ```bash
   git clone https://github.com/Hemsagar11/AegisShield.git
2. Navigate to the project directory:
    ```bash
    cd AegisShield
3. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate   # Linux/macOS
    venv\Scripts\activate      # Windows
4. Install dependencies:
    ```bash
    pip install -r requirements.txt
5. Configure VirusTotal API key: Set your API key in the configuration file.

## 5. Usage

**Running the Program:**
To start the program, run:
```bash
python aegis_shield.py
```
**Command-Line Arguments:**
```bash
--directory: Specify the directory to scan.
--file: Specify a single file to scan.
```
**Example Usage:**
```bash
python aegis_shield.py --directory /path/to/scan
python aegis_shield.py --file /path/to/file.exe
```


## 6. Testing

**Test Cases:**
- **Malware Samples:** Scanned known malware samples to verify detection.
- **Clean Files:** Ensured no false positives with clean files.
- **Edge Cases:** Tested with large files and various file types.

**Test Results:**
- Successfully detected all known malware samples.
- No false positives with clean files.
- Performance was acceptable for large files.

## 7. Limitations

**Known Issues:**
- Detection limited to known signatures.
- VirusTotal API rate limits may affect performance.

**Future Work:**
- Implement heuristic analysis.
- Add machine learning-based detection.

## 8. Future Enhancements

**Potential Features:**
- Real-time file monitoring.
- Improved scanning algorithms.
- Enhanced user interface with a web dashboard.

## 9. References

- [YARA Documentation](https://yara.readthedocs.io/)
- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [ClamAV Documentation](https://docs.clamav.net/)
