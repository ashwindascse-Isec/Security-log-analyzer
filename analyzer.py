import json

import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------
# Configuration
# -------------------------------
LOG_FILE = "mega_access.log"
SPIKE_THRESHOLD = 2

# -------------------------------
# Main analysis pipeline
# -------------------------------
def main():

    # Step 1: Parse log fields using regex
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

    # Step 2: Load and parse log data
    with open(LOG_FILE, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    df = pd.DataFrame(lines, columns=["raw_log"])
    parsed_df = df["raw_log"].str.extract(log_pattern)



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


   # -------------------------------
    # Step 7: Alerting (Fixed JSON Timestamp Error)
    # -------------------------------
    alert_payload = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "status": "CLEAR",
        "summary": "No suspicious traffic spikes detected.",
        "spike_details": {}
    }

    if not spike_minutes.empty:
        alert_payload["status"] = "ALERT"
        alert_payload["summary"] = "Suspicious traffic spike detected"
        
        # .rename(str) converts the underlying Pandas datetime index to strings flawlessly
        alert_payload["spike_details"] = spike_minutes.rename(str).to_dict()

    # This will now write cleanly to your directory!
    with open("security_alerts.json", "w") as alert_file:
        json.dump(alert_payload, alert_file, indent=4)
        print("\nsecurity_alerts.json successfully written to disk!")

    # Create a flag for unauthorized script engines
    parsed_df["is_bot"] = parsed_df["user_agent"].str.contains("curl|python-requests|sqlmap", case=False, na=False)
    malicious_bots = parsed_df[parsed_df["is_bot"] == True]
    print("\nIdentified Automated Hacking/Scraping Engines:")
    print(malicious_bots[["ip", "user_agent"]].drop_duplicates())


    # Step 7: Visualization
    plt.figure(figsize=(10, 5)) # Gives the chart a wider layout
    errors_per_min.plot(kind="line", marker="o", color="red") # Easier to spot spikes
    plt.xlabel("Time (per minute)")
    plt.ylabel("Number of 4xx errors")
    plt.title("4xx Errors Over Time")
    plt.grid(True, linestyle="--", alpha=0.6) # Helps you pinpoint the exact minute of an attack
    plt.tight_layout()

    plt.figure(figsize=(10, 5))
    errors_by_ip.head(5).plot(kind="bar")
    plt.xlabel("IP Address")
    plt.ylabel("4xx error count")
    plt.title("Top IPs Generating 4xx Errors")
    plt.xticks(rotation=90)
    plt.tight_layout()

    plt.figure(figsize=(10, 5))
    errors_by_user_agent.plot(kind="bar")
    plt.xlabel("User Agent")
    plt.ylabel("4xx error count")
    plt.title("User Agents Involved in Failures")
    plt.xticks(rotation=90)
    plt.tight_layout()

    plt.show()


   
if __name__ == "__main__":
    main()
