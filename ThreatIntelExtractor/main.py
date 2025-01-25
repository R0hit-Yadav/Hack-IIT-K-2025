import spacy
import utils
from pprint import pprint

# Load the SpaCy NLP model
nlp = spacy.load("en_core_web_sm")

def extract_threat_intelligence(report_text):
    """
    Extract threat intelligence from a natural language threat report.
    """
    # Initialize output dictionary
    output = {
        'IoCs': {
            'IP addresses': [],
            'Domains': [],
        },
        'TTPs': {
            'Tactics': [],
            'Techniques': [],
        },
        'Threat Actor(s)': [],
        'Malware': [],
        'Targeted Entities': [],
    }

    # Process the text with SpaCy
    doc = nlp(report_text)

    # Extract IoCs
    output['IoCs']['IP addresses'] = utils.extract_ip_addresses(report_text)
    output['IoCs']['Domains'] = utils.extract_domains(report_text)

    # Extract TTPs
    output['TTPs'] = utils.extract_ttps(report_text)

    # Extract Threat Actors
    output['Threat Actor(s)'] = utils.extract_entities(doc, ['ORG', 'PERSON'])

    # Extract Malware
    output['Malware'] = utils.extract_malware(report_text)

    # Extract Targeted Entities
    output['Targeted Entities'] = utils.extract_targeted_entities(doc)

    return output

if __name__ == "__main__":
    # Read the sample report
    with open('data/report_sample.txt', 'r') as file:
        report_text = file.read()

    # Extract intelligence
    intelligence = extract_threat_intelligence(report_text)

    # Display the results
    pprint(intelligence)
