import re
from collections import Counter, defaultdict
import csv

# Function to count requests per IP address
def count_requests_per_ip(log_data):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ip_addresses = [ip_pattern.search(line).group() for line in log_data if ip_pattern.search(line)]
    ip_counts = Counter(ip_addresses)
    return ip_counts

# Function to identify the most frequently accessed endpoint
def find_most_accessed_endpoint(log_data):
    endpoint_pattern = re.compile(r'\"(?:GET|POST|PUT|DELETE) (\S+)')
    endpoints = [endpoint_pattern.search(line).group(1) for line in log_data if endpoint_pattern.search(line)]
    endpoint_counts = Counter(endpoints)
    most_accessed = endpoint_counts.most_common(1)
    return most_accessed[0] if most_accessed else (None, 0)

# Function to detect suspicious activity
def detect_suspicious_activity(log_data, threshold=10):
    suspicious_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b.*401')
    failed_attempts = defaultdict(int)
    for line in log_data:
        if suspicious_pattern.search(line):
            ip = suspicious_pattern.search(line).group().split()[0]
            failed_attempts[ip] += 1
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return flagged_ips

# Function to save results to a CSV file
def save_results_to_csv(ip_counts, most_accessed, suspicious_activities, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])  # Blank line
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write Suspicious Activity
        writer.writerow([])  # Blank line
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main function to process the log file
def process_log_file(log_file, output_file):
    try:
        # Read log file
        with open(log_file, 'r') as file:
            log_data = file.readlines()

        # Count requests per IP
        ip_counts = count_requests_per_ip(log_data)

        # Find the most accessed endpoint
        most_accessed = find_most_accessed_endpoint(log_data)

        # Detect suspicious activity
        suspicious_activities = detect_suspicious_activity(log_data)

        # Display results
        print("IP Address           Request Count")
        print("-----------------------------------")
        for ip, count in ip_counts.items():
            print(f"{ip:<20} {count}")

        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        print("-----------------------------------")
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20} {count}")

        # Save results to CSV
        save_results_to_csv(ip_counts, most_accessed, suspicious_activities, output_file)
        print(f"\nResults saved to {output_file}")

    except FileNotFoundError:
        print(f"Error: The file '{log_file}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Specify the log file and output file
log_file_path = 'sample.log'
output_file_path = 'log_analysis_results.csv'
process_log_file(log_file_path, output_file_path)
