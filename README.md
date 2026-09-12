# PhishLens

PhishLens is a local-machine phishing email analysis tool designed to identify suspicious characteristics in `.eml` email files.

It analyzes multiple email security layers and combines their findings to produce an overall risk score and classification.

> **Project Type:** Cybersecurity / Email Security / Phishing Detection  
> **Environment:** Local Linux Machine  
> **Input:** `.eml` email files

---

## Features

### 📧 Email Parsing & Normalization

Extracts and normalizes important email information including:

- From
- To
- Reply-To
- Return-Path
- Subject
- Date
- Message-ID
- Plain-text body
- HTML body
- Attachments

### 🔗 URL Analysis

Extracts and analyzes URLs found in email bodies.

PhishLens detects suspicious URL characteristics including:

- HTTP instead of HTTPS
- IP addresses used as hostnames
- Unusual ports
- Deep subdomains
- Suspicious keywords
- Long URLs
- Redirect parameters
- Multiple query parameters
- `@` symbols
- Percent-encoded URLs

### 📎 Attachment Analysis

Analyzes email attachments including:

- File names
- File extensions
- MIME types
- File size
- SHA-256 hashes
- Suspicious filenames
- Dangerous extensions
- Dangerous MIME types
- MIME inconsistencies
- Multiple attachments
- Nested multipart emails

### 📋 Header Analysis

Checks email headers for suspicious characteristics including:

- From and Reply-To mismatches
- Display-name spoofing
- Missing important headers
- Suspicious header characteristics

### 🔐 Authentication Analysis

Analyzes email authentication information including:

- SPF
- DKIM
- DMARC
- Authentication-Results

### 🔎 Correlation Analysis

Correlates findings across different detection categories instead of treating every indicator independently.

Examples include:

- URL + Header
- URL + Attachment
- Header + Authentication
- Multiple independent detection categories
- Multi-layer phishing evidence

### 🎯 Risk Scoring

PhishLens produces an overall risk score from `0` to `100`.

| Score | Risk Level |
|---:|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

---

## Technology Stack

### Backend

- Python
- FastAPI
- Uvicorn
- Pytest

### Frontend

- HTML5
- CSS3
- JavaScript

### Development Environment

- Linux
- Git
- GitHub
- Python Virtual Environment

---

## Architecture

```text
                    .eml Email
                        |
                        v
                Email Parser
                        |
                        v
              Email Normalizer
                        |
        +---------------+---------------+
        |               |               |
        v               v               v
   URL Analyzer   Attachment       Header Analyzer
                      Analyzer
        |               |               |
        +---------------+---------------+
                        |
                        v
              Authentication
                  Analyzer
                        |
                        v
               Correlation Engine
                        |
                        v
                Detection Engine
                        |
                        v
                  Risk Scoring
                        |
                        v
                FastAPI Backend
                        |
                        v
                 Web Dashboard
```

## Detection Pipeline

PhishLens follows a layered detection approach:

```text
Email Input
    |
    v
Parsing
    |
    v
Normalization
    |
    +---- URL Analysis
    |
    +---- Attachment Analysis
    |
    +---- Header Analysis
    |
    +---- Authentication Analysis
    |
    v
Correlation Analysis
    |
    v
Detection Engine
    |
    v
Risk Score
    |
    v
Risk Classification
    |
    v
Dashboard
```

## Project Structure

```text
PhishLens/
│
├── backend/
│   │
│   ├── app/
│   │   ├── analyzers/
│   │   │   ├── attachment_analyzer.py
│   │   │   ├── authentication_analyzer.py
│   │   │   ├── detection_engine.py
│   │   │   ├── email_correlator.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── link_analyzer.py
│   │   │   ├── url_analyzer.py
│   │   │   └── url_extractor.py
│   │   │
│   │   ├── engine/
│   │   │   └── detection_engine.py
│   │   │
│   │   ├── models/
│   │   │   ├── email_model.py
│   │   │   └── url_model.py
│   │   │
│   │   ├── parsers/
│   │   │   ├── email_normalizer.py
│   │   │   └── email_parser.py
│   │   │
│   │   └── api.py
│   │
│   ├── test_attachment_analyzer.py
│   ├── test_authentication_analyzer.py
│   ├── test_detection_engine.py
│   ├── test_detection_scenarios.py
│   ├── test_email_correlator.py
│   ├── test_header_analyzer.py
│   ├── test_link_analyzer.py
│   ├── test_link_mismatch.py
│   ├── test_normalizer.py
│   ├── test_parser.py
│   ├── test_url_analyzer.py
│   └── test_url_extractor.py
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── samples/
│   ├── sample_attachments.eml
│   ├── sample_authentication.eml
│   ├── sample_clean.eml
│   ├── sample_link_mismatch.eml
│   ├── sample_multipart.eml
│   ├── sample_phishing.eml
│   ├── sample_received.eml
│   ├── sample_urls.eml
│   └── test_*.eml
│
├── docs/
│
├── .gitignore
└── README.md
```

## Testing

PhishLens includes automated tests covering multiple components of the detection pipeline.

Test coverage includes:

- Email parsing
- Email normalization
- URL extraction
- URL analysis
- URL edge cases
- Link mismatch detection
- Attachment analysis
- Authentication analysis
- Header analysis
- Correlation analysis
- Detection engine
- Detection scenarios
- MIME-related edge cases
- Multiple attachments
- Nested multipart emails
- Missing attachment filenames
- Missing email headers

Sample emails are also used for end-to-end API testing.

## Sample Emails

The project contains intentionally created training samples for testing different detection scenarios.

### Clean Email

`sample_clean.eml`

Expected result:

- Risk Score: `0`
- Risk Level: `LOW`

### Phishing Email

`sample_phishing.eml`

Tests combinations of:

- Suspicious URL
- HTTP URL
- Suspicious keyword
- Reply-To mismatch
- Display-name spoofing

### URL Analysis Sample

`sample_urls.eml`

Tests multiple URL indicators including:

- HTTP
- IP address hostname
- Unusual port
- Deep subdomain
- Suspicious keyword
- Long URL
- Redirect parameters
- Multiple query parameters
- `@` symbol
- Percent encoding

### Authentication Sample

`sample_authentication.eml`

Tests:

- SPF failure
- DKIM failure
- DMARC failure
- Reply-To mismatch
- Display-name spoofing
- Header + authentication correlation

### Attachment Sample

`sample_attachments.eml`

Tests:

- Dangerous executable attachment
- Suspicious filename
- Double extension
- Multiple attachment findings

---

## Running PhishLens

### Start the Backend

Navigate to the backend directory:

```bash
cd ~/Phishlens/backend
```

Activate the Python virtual environment:

```bash
source venv/bin/activate
```

Start the FastAPI server:

```bash
uvicorn app.api:app --reload
```

The API runs locally at:

```text
http://127.0.0.1:8000
```

### Analyze an Email Using the API

From the backend directory:

```bash
curl -X POST \
    -F "file=@../samples/sample_phishing.eml" \
    http://127.0.0.1:8000/analyze
```

The API returns structured JSON containing:

- Email metadata
- URL results
- Attachment results
- Header results
- Authentication results
- Correlation results
- Overall score
- Overall risk
- Detection summary

### Run the Test Suite

From the backend directory:

```bash
pytest
```

---

## Security Design

PhishLens is designed as a defensive cybersecurity project.

The tool performs static analysis of `.eml` files rather than executing email attachments or visiting suspicious URLs.

The analysis is performed locally to reduce the need to upload potentially sensitive email content to external services.

## Current Limitations

PhishLens currently focuses on static analysis of `.eml` files.

It does not currently:

- Execute attachments
- Detonate malware
- Visit suspicious URLs
- Perform live DNS reputation checks
- Query external threat-intelligence platforms
- Verify SPF/DKIM/DMARC through live DNS lookups
- Guarantee that an email is malicious based only on its score

Risk scores should therefore be treated as indicators for investigation rather than absolute proof of phishing.

## Future Improvements

Potential future enhancements include:

- Threat intelligence integration
- Domain reputation checking
- DNS-based SPF validation
- DKIM verification
- DMARC policy validation
- WHOIS information
- URL reputation services
- Malware hash reputation
- YARA-based attachment analysis
- Machine-learning-based classification
- Email campaign correlation
- Authentication improvements
- User authentication
- Analysis history
- Exportable investigation reports
- SOC/DFIR investigation workflow integration

## Cybersecurity Skills Demonstrated

This project demonstrates practical experience with:

- Phishing analysis
- Email security
- Email header analysis
- Email authentication
- SPF / DKIM / DMARC
- URL analysis
- Link mismatch detection
- MIME analysis
- Attachment analysis
- Hashing
- Risk scoring
- Detection engineering
- Security event correlation
- Python development
- REST APIs
- FastAPI
- Automated testing
- Linux
- Git
- GitHub

## Project Purpose

PhishLens was developed as a cybersecurity portfolio project to demonstrate practical understanding of phishing detection, email security analysis, detection engineering, and security automation.

The project is intended for:

- Cybersecurity portfolio development
- SOC analyst practice
- Email security investigation
- Detection engineering practice
- Security analysis demonstrations

## Author

**RUFSHANHARIF**

Cybersecurity Project — PhishLens

