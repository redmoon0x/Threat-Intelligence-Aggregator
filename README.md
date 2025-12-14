# Threat Intelligence Aggregator

Hi  👋

Here is the guide for the Threat Intelligence Aggregator tool. This tool is designed to help you process and organize Indication of Compromise (IOC) data from various sources automatically.

## 🚀 Quick Start

### 1. Prerequisites
Make sure you have Python installed. You also need to install the required libraries:

```bash
pip install -r requirements.txt
```

### 2. How to Run It

You can run the tool in two ways using the command line:

**Option A: Process everything in the `feeds/` folder (Default)**
Just run the script without any arguments. It will look for all `.csv`, `.json`, and `.txt` files in the `feeds` directory.
```bash
python main.py
```

**Option B: Process a specific file or folder**
If you have a specific feed file you want to check, use the `-f` flag:
```bash
python main.py -f path/to/your/feed.csv
```
Or pointing to a different directory:
```bash
python main.py -f path/to/custom_feeds_folder/
```

## 🧠 How It Works

The tool follows a strict pipeline to ensure data quality:

1.  **Loader**: Reads raw data from files or URLs.
2.  **Parsers**: Auto-detects the format (CSV, JSON, or Text) and extracts potential indicators (IPs, Domains, URLs, Hashes).
3.  **Validator**: Checks if the extracted indicators are valid (e.g., checks if an IP address is real). Invalid data is silently discarded.
4.  **Normalizer**: Standardizes everything into a common format with timestamps.
5.  **Correlator**: The "Brain" of the operation. It counts how many times an indicator appears across different feeds.
    *   **High Severity**: Appears in 4+ sources.
    *   **Medium Severity**: Appears in 2-3 sources.
    *   **Low Severity**: Unique to 1 source.
6.  **Output**: Generates clean blocklists and a summary report.

## 📂 Where are my results?

Check the `output/` folder!

*   **`output/blocklists/`**: Contains ready-to-use text files for firewalls or security tools.
    *   `firewall_ips.txt`
    *   `malicious_domains.txt`
    *   `malicious_urls.txt`
    *   `hash_blocklist.txt`
*   **`output/reports/`**: Contains `summary_report.txt` which gives you a high-level overview of what was processed.

---

## 🏗️ Developer Guide (How it was built)

If you need to build something similar or extend this project, here is the architectural breakdown:

### Project Structure
The project uses a **Modular Design** to keep things clean and separated.

*   `core/`: Contains the pure business logic.
    *   `validator.py`: Pure logic to say "Yes this is valid" or "No".
    *   `normalizer.py`: Transforms messy input into a standard dictionary format.
    *   `correlator.py`: The state engine that aggregates counts and severity.
*   `loaders/`: Handles Input/Output (I/O). It just fetches raw text, it doesn't care what it contains.
*   `parsers/`: The translation layer. Each file type has its own parser class.

### Design Patterns Used
1.  **Strategy Pattern (Parsers)**: The `main.py` selects the correct parser based on file extension. To add a new format (e.g., XML), you just write `xml_parser.py` and add it to the `parsers` dictionary. You don't need to rewrite the main logic.
2.  **Pipeline Pattern**: Data flows linearly: `Load -> Parse -> Validate -> Normalize -> Correlate`.
3.  **Aggregator Pattern**: Data is collected into a central `Correlator` class which holds the state until processing is finished.

### How to extend it?
**Scenario: You want to add XML support.**

1.  Create `parsers/xml_parser.py`.
2.  Implement a `parse(content)` method that yields IOcs.
3.  In `main.py`, import it and add it to the `self._parsers` dict:
    ```python
    self.parsers = {
        '.csv': CsvParser(),
        '.xml': XmlParser() # New!
    }
    ```
    That's it! The rest of the system handles it automatically.

---
Happy Hunting & Coding! 🕵️‍♀️💻

