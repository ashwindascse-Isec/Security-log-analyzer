# Security Log Analyzer (Apache Access Logs)

## Project Overview
This project analyzes real-world Apache web server access logs to identify suspicious client-side behavior using data analysis and automated threat detection techniques. 

The focus is on parsing, filtering, and detecting abnormal spikes in `4xx` HTTP client errors to uncover:
- Automated brute-force credential stuffing attempts
- Scanning, fuzzing, and directory enumeration targeting restricted endpoints
- Automated script-engine reconnaissance bots (`curl`, `python-requests`, etc.)

The utility combines regex log parsing, vectorized time-series downsampling, behavioral correlation, and automated alert telemetry to surface potential security issues seamlessly.

> **Scope:** This project is designed for defensive security auditing, behavioral telemetry analysis, and automated alerting workflows.

---

## Why This Project Matters
Web servers generate massive volumes of unstructured log text, making manual auditing impossible. In a modern Security Operations Center (SOC) or backend infrastructure layer:
- Attacks appear as compressed, multi-threaded **bursts**, not isolated incidents.
- Modern threats require behavioral telemetry analysis over strict signature matching.
- Context (temporal frequency, structural correlation, and client payloads) is vital to identifying malicious intent.

This project demonstrates how scalable, production-grade security insights and automated telemetry alerts can be engineered entirely through highly efficient data analysis fundamentals and defensive scripting.

---

## Technical Architecture & Core Features
The tool executes a modular data-processing pipeline:

1. **Defensive Line-by-Line Ingestion:** Streamlines raw, unstructured files dynamically while cleanly filtering empty lines or broken syntax records.
2. **Regex Field Extraction:** Utilizes an optimized, multi-group Regular Expression string to securely map IPs, timestamps, HTTP verbs, resource paths, status codes, and User-Agent payloads into structured frames.
3. **Time-Series Serialization & Alignment:** Downsamples and floors timezone-aware datetime objects into strict 1-minute buckets to calculate traffic velocity accurately.
4. **Behavioral Telemetry Filtering:** Isolates client-side anomalies by querying `4xx` ranges to separate standard user traffic from malicious failures.
5. **Heuristic Engine Bot Flagging:** Applies defensive string evaluation arrays to detect explicit script-engine headers (such as `curl`, `python-requests`, or `sqlmap`) involved in unauthorized directory probing.
6. **Automated SIEM JSON Alerting Hub:** Monitors velocity against static threshold boundaries. Generates an instant lifecycle report (`security_alerts.json`) outputting state conditions (`CLEAR` or `ALERT`) alongside structured threat details.
7. **Vectorized Visual Distributions:** Generates line and bar configurations via Matplotlib, optimizing data density so security anomalies are identifiable instantly.

---

## Project Structure
```text
log-analyzer/
├── main.py                # Main analysis script & threat detection engine
├── mega_access.log        # Production-scale Apache log dataset (5,000+ entries)
├── security_alerts.json   # Real-time automated JSON alert telemetry file
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation
```
## Technologies Used
- **Python 3.10+**
- **Pandas:** Vectorized data normalization, grouping, and statistical aggregation.
- **Matplotlib:** Time-series line graphs and categorical behavioral charts.
- **JSON:** Structured machine-to-machine alert telemetry logging.
- **Regular Expressions (`re`):** High-speed unstructured text parsing.

---

## Key Security Insights Generated
By running the engine against a dataset containing **over 5,000+ production-scale log entries**, the following behavior profiles were successfully exposed and visualized:

- **Automated Brute-Force Wave:** Identified malicious sub-second request bursts from localized IPs targeting `/login` endpoints resulting in continuous `401 Unauthorized` states.
- **Privilege / Directory Probing:** Captured automated endpoint fuzzing targeting administrative pages (`/admin`), triggering dense groups of `403 Forbidden` responses.
- **Script-Engine Footprints:** Uncovered clear correlations between malicious error spikes and automated command-line frameworks, successfully isolating non-browser scrapers via deep User-Agent analysis.

---

## Sample Automated Alert Outputs

When an attack profile trips the velocity boundaries (`SPIKE_THRESHOLD`), the engine dynamically writes real-time JSON alert states.

### Threat Detected State (`ALERT`):
```json
{
    "timestamp": "2026-05-30T10:14:22.842105",
    "status": "ALERT",
    "summary": "Suspicious traffic spike detected",
    "spike_details": {
        "2020-10-10 13:51:00+05:30": 4,
        "2020-10-10 13:55:00+05:30": 5
    }
}
```
### Baseline Safe State (CLEAR):
```json
{
    "timestamp": "2026-05-30T10:15:00.103945",
    "status": "CLEAR",
    "summary": "No suspicious traffic spikes detected.",
    "spike_details": {}
}
```
## Installation & Execution

1. Clone the Environment
```bash
git clone [https://github.com/your-username/log-analyzer.git](https://github.com/your-username/log-analyzer.git)
cd log-analyzer
```
2. Configure Dependencies
```bash
pip install -r requirements.txt
```
(Alternatively: pip install pandas matplotlib)
3. Run the Engine
```bash
python analyzer.py
```

## Visual Analysis Output Examples
The visualization pipeline renders three clear, presentation-ready frames:
1. **Time-Series Timeline Line Chart:** Tracks the exact minute-by-minute frequency curve of incoming client errors to help pinpoint block windows.
2. **Top Error-Generating IPs:** Categorical distribution displaying the highest risk-contributing infrastructure sources.
3. **User-Agent Footprint Profile:** Exposes the distribution of browser headers vs. script tools active during failure windows.

---

## Limitations
- **Threshold Dependency:** Anomaly detection depends on static velocity parameters.
- **Context Boundaries:** Lacks native external integrations such as live Geo-IP localization data feeds or IP reputation database lookups.
- **Signature Independence:** Focuses purely on behavioral rates rather than analyzing internal packet payloads (e.g., cross-site scripting strings).

---

## Future Enhancements
- **Geo-IP Enrichment:** Integrating localization databases to bind physical region profiles to malicious IP tracking lines.
- **Attack Payload Profiling:** Adding deeper layer signature decoding to intercept precise SQLi/XSS parameters.
- **SIEM Stream Integration:** Extending the JSON alerting file module into a live network stream webhook or notification client loop.

---

## Key Learning Outcomes
- Advanced data engineering tactics using vectorized Pandas structures rather than resource-heavy Python loops.
- Time-series aggregation and manipulation logic over complex datetime index boundaries.
- Modern security telemetry engineering, bridging analytical outputs to machine-readable alert hooks (`JSON`).
- Structuring modular, production-grade, and easily auditable backend Python code.
