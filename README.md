# Security Log Analyzer (Apache Access Logs)

## Project Overview

This project analyzes Apache web server access logs to identify suspicious client-side behavior using basic cybersecurity and data analysis techniques.

The focus is on detecting abnormal spikes in 4xx HTTP errors (client errors), which often indicate:

- Brute-force login attempts  
- Automated probing of restricted endpoints  
- Scanning or enumeration activity  

The project combines log parsing, time-based analysis, behavioral correlation, and visualization to surface potential security issues.

Scope: This project is intended for exploratory security analysis and learning purposes, not production deployment.

---

## Why This Project Matters

Web servers generate massive volumes of logs, but raw logs are difficult to analyze manually.

In real-world security monitoring:

- Attacks often appear as bursts, not isolated events  
- Suspicious activity is usually behavioral, not signature-based  
- Context (time, frequency, and tool used) matters more than individual errors  

This project demonstrates how meaningful security insights can be extracted from logs without machine learning,
using clear logic and data analysis fundamentals.

---

## What This Project Does

The analyzer performs the following steps:

- Parses raw Apache access logs using regular expressions  
- Converts timestamps into timezone-aware datetime objects  
- Buckets requests per minute to detect bursty behavior  
- Filters 4xx HTTP errors as security-relevant signals  
- Detects spike minutes where error frequency exceeds a threshold  
- Analyzes behavior by IP and User-Agent  
- Visualizes anomalies to make patterns obvious at a glance  

---

## Key Insights Generated

The analysis produces several security-relevant insights:

- Identification of time windows with abnormal 4xx error spikes  
- Detection of IP addresses responsible for the majority of failures  
- Correlation between non-browser user agents (e.g., curl, python-requests) and repeated failures  
- Clear separation between normal browsing behavior and automated activity  

These insights are derived entirely from log behavior, without relying on predefined attack signatures.

---

## Visual Analysis

The project generates clear visual outputs to support analysis:

- 4xx error frequency over time (per minute)  
- Top IPs generating client-side errors  
- User agents most frequently involved in failures  

The visualizations are designed so that anomalies are visible without requiring inspection of the underlying code.

---

## Technologies Used

- Python  
- Pandas for data parsing and analysis  
- Matplotlib for visualization  
- Regular expressions for log parsing  

---

## Project Structure

```text
log-analyzer/
├── analyzer.py          # Main analysis script
├── apache_access.log    # Sample Apache access log
├── requirements.txt     # Project dependencies
└── README.md            # Project documentation

```



---

## How to Run

Install dependencies:

```bash
pip install pandas matplotlib

```

```bash
python analyzer.py

```

## Limitations


This project intentionally keeps detection logic simple and transparent. As a result:

- Spike detection relies on static thresholds

- No IP reputation or Geo-IP enrichment is performed

- Specific attack payloads (e.g., SQL injection signatures) are not detected

- The analysis is not designed for real-time or production monitoring

- These limitations are accepted to maintain clarity and explainability.




## Possible Extensions and Future Work


The following enhancements could be added in future iterations:

- Geo-IP enrichment to add geographic context to suspicious IPs

- Signature-based detection for common web attacks

- Longer time-window correlation for slow or low-volume attacks

- Exporting results to structured reports or dashboards

- These features were intentionally left out to avoid unnecessary complexity.



## Key Learning Outcomes

Through this project, the following skills were developed:

- Practical log parsing and data cleaning

- Time-series analysis for anomaly detection

- Behavioral security analysis beyond simple IP counting

- Writing clear, explainable, and defensible analysis code



## Final Notes

This project emphasizes clarity, correctness, and interpretability over advanced tooling or opaque techniques. 
All detection logic is intentionally transparent and designed to be easy to reason about and explain in technical discussions.