import csv
from collections import Counter, defaultdict
import re

# File path for the log and results csv files
log_file_path = 'sample.log'
results_csv_path = 'log_analysis_results.csv'

# Set the maximum number of failed login attempts
failed_logins = 5

def parse_log_file(file_path):
     
    ip_request_counts = Counter()
    endpoint_access_counts = Counter()
    failed_login_counts = defaultdict(int)


    with open(file_path, 'r') as file:
        for log_entry in file:
            # Find and get the IP address from each log entry
            ip_address_match = re.match(r'^([\d\.]+)', log_entry)
            if ip_address_match:
                ip_address = ip_address_match.group(1)
                ip_request_counts[ip_address] += 1

            # Find and get the endpoint from each log entry
            endpoint_match_result = re.search(r'"[A-Z]+\s+([^\s]+)\s+HTTP', log_entry)
            if endpoint_match_result:
                endpoint_url = endpoint_match_result.group(1)
                endpoint_access_counts[endpoint_url] += 1

            # Check if there is a failed login attempt (status 401)
            if '401' in log_entry or 'Invalid credentials' in log_entry:
                if ip_address_match:
                    failed_login_counts[ip_address] += 1

    return ip_request_counts, endpoint_access_counts, failed_login_counts

def output_results(ip_request_counts, endpoint_access_counts, failed_login_counts, results_csv_path):
     
    # Show the number of requests made by each IP address
    print("IP Address          Request Count")
    for ip_address, count in ip_request_counts.most_common():
        print(f"{ip_address:18}{count}")

    #  find and show the most visited endpoints
    top_accessed_endpoint, top_endpoint_access_count = endpoint_access_counts.most_common(1)[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{top_accessed_endpoint} (Accessed {top_endpoint_access_count} times)")

    # Find suspicious activity 
    print("\nSuspicious Activity Detected:")
    print("IP Address          Failed Login Attempts")
    suspicious_ip_counts = {ip: count for ip, count in failed_login_counts.items() if count > failed_logins}
    for ip_address, count in suspicious_ip_counts.items():
        print(f"{ip_address:18}{count}")

    # Save the results in CSV file
    with open(results_csv_path, mode='w', newline='') as csv_output_file:
        csv_file_writer = csv.writer(csv_output_file)

        # number of requests for each IP
        csv_file_writer.writerow(['Requests per IP'])
        csv_file_writer.writerow(['IP Address', 'Request Count'])
        for ip_address, count in ip_request_counts.most_common():
            csv_file_writer.writerow([ip_address, count])

        # most visited endpoint
        csv_file_writer.writerow([])
        csv_file_writer.writerow(['Most Accessed Endpoint'])
        csv_file_writer.writerow(['Endpoint', 'Access Count'])
        csv_file_writer.writerow([top_accessed_endpoint, top_endpoint_access_count])

        # Write suspicious activity
        csv_file_writer.writerow([])
        csv_file_writer.writerow(['Suspicious Activity'])
        csv_file_writer.writerow(['IP Address', 'Failed Login Count'])
        for ip_address, count in suspicious_ip_counts.items():
            csv_file_writer.writerow([ip_address, count])

# start the main process 
if __name__ == "__main__":
    ip_request_counts, endpoint_access_counts, failed_login_counts = parse_log_file(log_file_path)
    output_results(ip_request_counts, endpoint_access_counts, failed_login_counts, results_csv_path)
    print(f"\nAnalysis results saved to {results_csv_path}")
