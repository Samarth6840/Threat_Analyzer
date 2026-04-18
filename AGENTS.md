# Repository Guidelines

A web-based threat analysis tool designed to parse Apache access logs and visualize security threats.

## Project Structure & Module Organization

The application follows a standard Flask structure with logic decoupled into core modules:

- `app.py`: Main entry point containing Flask routes and application configuration.
- `core/`: Primary business logic:
    - `log_parser.py`: Regex-based utilities for parsing Apache logs.
    - `mapreduce.py`: Parallel processing engine using `concurrent.futures`.
    - `threat_intel.py`: Geolocation and threat score enrichment.
    - `database.py`: SQLAlchemy models and database interaction logic.
- `scripts/`: Utility scripts for development and testing:
    - `generate_sample_logs.py`: Creates synthetic log data for demonstration.
    - `live_stream.py`: Simulates live log ingestion via SocketIO.
- `templates/`: Jinja2 HTML templates for the dashboard and history views.
- `report_generator.py`: PDF report generation using `reportlab`.

## Build, Test, and Development Commands

### Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running the Application
```bash
python3 app.py
```

### Development Utilities
- **Generate Sample Logs**: `python3 scripts/generate_sample_logs.py`
- **Simulate Live Stream**: `python3 scripts/live_stream.py`

## Coding Style & Naming Conventions

The project adheres to PEP 8 standards for Python code. While no formal linter is configured, maintain consistency with existing code:

- Use snake_case for functions and variables.
- Use CamelCase for class names.
- Keep logic modules within the `core/` directory.

## Commit Guidelines

Follow the established pattern of concise commit messages. While the history is minimal, aim for descriptive summaries of changes.
