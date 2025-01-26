# Threat Intelligence Extractor

This project extracts structured threat intelligence from natural language threat reports. It identifies **Indicators of Compromise (IoCs)**, **Tactics, Techniques, and Procedures (TTPs)**, **Threat Actors**, **Malware**, and **Targeted Entities**, providing visualizations and threat severity scoring.

## **Features**
- Extracts and displays:
  - **IoCs:** IP Addresses, Domains
  - **TTPs:** Tactics and Techniques
  - **Threat Actors:** Groups/Organizations involved
  - **Malware:** Known malware names
  - **Targeted Entities:** Organizations or industries
- **Threat Severity Scoring:** Dynamically calculates the severity of the threat based on extracted intelligence.
- **Visualizations:** Bar charts for IoCs, TTPs, and Malware counts.
- **Manage Malware:** Add or remove malware names dynamically.
- **Downloadable JSON:** Extracted data can be downloaded for further use.

---

## **Requirements**
Before running the application, ensure you have the following installed:

- **Python 3+**
- **Required Libraries** (Install via pip):
- 
  `cd ThreatIntelExtractor`

  `pip install -r requirements`

SpaCy Language Model: `python -m spacy download en_core_web_sm`

  `pip install streamlit spacy matplotlib`


for run application 
`streamlit run main.py` 
