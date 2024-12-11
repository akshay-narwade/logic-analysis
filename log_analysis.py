import re
import csv
from collections import defaultdict, Counter

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Read and parse the log file into lines."""
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except FileNotFoundError:
        print(f"Error: The log file '{file_path}' was not found.")
        exit()

def count_requests_per_ip(logs):
    """Count the number of requests made by each IP address."""
    ip_counts = defaultdict(int)
    for line in logs:
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            ip = ip_match.group(1)
            ip_counts[ip] += 1
    return dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True))

def most_frequently_accessed_endpoint(logs):
    """Find the most frequently accessed endpoint."""
    endpoint_counts = Counter()
    for line in logs:
        endpoint_match = re.search(r'"[A-Z]+ (\/\S*) HTTP\/\d+\.\d+"', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counts[endpoint] += 1
    most_common = endpoint_counts.most_common(1)
    return most_common[0] if most_common else ("None", 0)

def detect_suspicious_activity(logs, threshold=FAILED_LOGIN_THRESHOLD):
    """Identify IP addresses with failed login attempts exceeding the threshold."""
    failed_logins = defaultdict(int)
    for line in logs:
        if "401" in line or "Invalid credentials" in line:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_logins[ip] += 1
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity, output_file):
    """Save the analysis results to a CSV file."""
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests_per_ip.items():
            writer.writerow([ip, count])

        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    """Main function to execute the log analysis."""
    # Parse log file
    logs = parse_log_file(LOG_FILE)

    # Analyze logs
    requests_per_ip = count_requests_per_ip(logs)
    most_accessed_endpoint = most_frequently_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Display results
    print("\nRequests per IP:")
    for ip, count in requests_per_ip.items():
        print(f"{ip:<15} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<15} {count}")

    # Save to CSV
    save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity, OUTPUT_CSV)
    print(f"\nResults saved to '{OUTPUT_CSV}'")

if __name__ == "__main__":
    main()
