import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------
# Configuration
# -------------------------------
LOG_FILE = "apache_access.log"
SPIKE_THRESHOLD = 2

# -------------------------------
# Main analysis pipeline
# -------------------------------
def main():
    # Step 1: Load raw log file
    df = pd.read_csv(LOG_FILE, header=None)

    # Step 2: Parse log fields using regex
    log_pattern = (
        r'(?P<ip>\S+) '
        r'\S+ \S+ '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d+) '
        r'\S+ '
        r'"[^"]*" '
        r'"(?P<user_agent>[^"]+)"'
    )

    parsed_df = df[0].str.extract(log_pattern)

    # Step 3: Clean & normalize data
    parsed_df = parsed_df.dropna()
    parsed_df["status"] = parsed_df["status"].astype(int)
    parsed_df["timestamp"] = pd.to_datetime(
        parsed_df["timestamp"],
        format="%d/%b/%Y:%H:%M:%S %z"
    )

    parsed_df = parsed_df.sort_values("timestamp")
    parsed_df["minute"] = parsed_df["timestamp"].dt.floor("min")

    # Step 4: Focus on client-side errors (4xx)
    errors_4xx = parsed_df[
        (parsed_df["status"] >= 400) & (parsed_df["status"] < 500)
    ]

    # Step 5: Time-based spike detection
    errors_per_min = (
        errors_4xx
        .groupby("minute")
        .size()
    )

    spike_minutes = errors_per_min[
        errors_per_min > SPIKE_THRESHOLD
    ]

    print("Suspicious 4xx spikes:")
    print(spike_minutes)

    # Step 6: Behavioral analysis
    errors_by_ip = (
        errors_4xx
        .groupby("ip")
        .size()
        .sort_values(ascending=False)
    )

    errors_by_user_agent = (
        errors_4xx
        .groupby("user_agent")
        .size()
        .sort_values(ascending=False)
    )

    ip_ua_correlation = (
        errors_4xx
        .groupby(["ip", "user_agent"])
        .size()
        .sort_values(ascending=False)
    )

    print("\n4xx errors by IP:")
    print(errors_by_ip)

    print("\n4xx errors by User-Agent:")
    print(errors_by_user_agent)

    print("\nIP + User-Agent correlation:")
    print(ip_ua_correlation)

    # Step 7: Visualization
    plt.figure()
    errors_per_min.plot(kind="bar")
    plt.xlabel("Time (per minute)")
    plt.ylabel("Number of 4xx errors")
    plt.title("4xx Errors Over Time")
    plt.xticks(rotation=90)
    plt.tight_layout()

    plt.figure()
    errors_by_ip.head(5).plot(kind="bar")
    plt.xlabel("IP Address")
    plt.ylabel("4xx error count")
    plt.title("Top IPs Generating 4xx Errors")
    plt.xticks(rotation=90)
    plt.tight_layout()

    plt.figure()
    errors_by_user_agent.plot(kind="bar")
    plt.xlabel("User Agent")
    plt.ylabel("4xx error count")
    plt.title("User Agents Involved in Failures")
    plt.xticks(rotation=90)
    plt.tight_layout()

    plt.show()


if __name__ == "__main__":
    main()
