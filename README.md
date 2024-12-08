# Log File Analysis Script

This Python script analyzes server log files to extract useful insights, such as the number of requests per IP address, the most frequently accessed endpoint, and any suspicious activity based on failed login attempts.

## Features
- **Requests per IP Address**: Counts how many requests were made by each IP.
- **Top Accessed Endpoint**: Identifies the most frequently accessed URL or endpoint.
- **Suspicious Activity Detection**: Flags IPs with excessive failed login attempts.

## File Structure
- **`sample.log`**: The log file to be analyzed.
- **`log_analysis_results.csv`**: The output file containing the analysis results.

## How to Use
1. Already attached one log file named as "sample.log". If you want to add more log files, place the log file (`sample.log`) in the same directory as the script.
2. Open the script and adjust the `log_file_path` and `results_csv_path` variables if needed.
3. Run the script:
   ```bash
   python log_analysis.py
