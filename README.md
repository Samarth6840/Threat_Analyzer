# Threat Analyzer

A comprehensive web-based threat analysis tool that parses Apache access logs to detect and visualize security threats in real-time.

## Features

- **Log Parsing**: Efficiently parses Apache access logs using regex patterns
- **Threat Detection**: Identifies multiple threat types:
  - Brute Force attacks
  - SQL Injection attempts
  - DDoS attacks
  - Vulnerability scanners
- **Geolocation Intelligence**: Enriches IP addresses with location data and abuse scores
- **Interactive Dashboard**: Modern web interface with:
  - Real-time statistics cards
  - Interactive world map showing threat locations
  - Detailed threat tables with severity indicators
- **Parallel Processing**: Uses MapReduce pattern for high-performance analysis
- **PDF Reports**: Generates professional incident reports
- **Sample Data Generation**: Creates realistic test log data for demonstration

## Technology Stack

- **Backend**: Python 3, Flask web framework
- **Frontend**: HTML5, CSS3, JavaScript, Leaflet.js for mapping
- **Processing**: Concurrent.futures for parallel execution
- **Reporting**: ReportLab for PDF generation
- **APIs**: IP-API.com for geolocation, AbuseIPDB for threat intelligence

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the application:
   ```bash
   python3 app.py
   ```
2. Open your browser to `http://localhost:5000`
3. Upload an Apache access log file or paste log entries
4. View the analysis results on the interactive dashboard
5. Download a PDF report of the findings

## Sample Data

Generate sample log data for testing:
```bash
python3 generate_sample_logs.py
```

## Architecture

- `app.py`: Main Flask application with web routes
- `log_parser.py`: Regex-based log parsing utilities
- `mapreduce.py`: Parallel processing implementation
- `threat_intel.py`: Geolocation and threat intelligence enrichment
- `report_generator.py`: PDF report creation
- `templates/`: Jinja2 HTML templates for the web interface

## Security Features

- Input validation and sanitization
- Safe file upload handling
- No persistent data storage of sensitive logs
- Client-side and server-side validation

## Performance

- Parallel processing for large log files
- Efficient regex patterns for log parsing
- Cached API responses for geolocation data
- Optimized database queries (when applicable)

## Contributing

This project demonstrates expertise in:
- Web application development with Flask
- Data processing and analysis
- Security threat detection algorithms
- Interactive data visualization
- API integration and data enrichment
- Professional UI/UX design
- Concurrent programming in Python

#images
<img width="322" height="759" alt="image" src="https://github.com/user-attachments/assets/b7684772-04d5-4106-83a9-5e74e549c7f9" />

<img width="750" height="818" alt="image" src="https://github.com/user-attachments/assets/2b4f9598-2178-400c-adec-59ad29351ed7" />


## License

MIT License - feel free to use for learning and portfolio purposes.
