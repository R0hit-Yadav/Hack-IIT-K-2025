import re

def extract_ip_addresses(text):
    """
    Extract IP addresses using regular expressions.
    """
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(pattern, text)

def extract_domains(text):
    """
    Extract domain names using regular expressions.
    """
    pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    return re.findall(pattern, text)

def extract_ttps(text):
    """
    Extract tactics and techniques (dummy data for now).
    """
    tactics = [['TA0001', 'Initial Access'], ['TA0002', 'Execution']]
    techniques = [['T1566.001', 'Spear Phishing Attachment']]
    return {'Tactics': tactics, 'Techniques': techniques}

def extract_entities(doc, entity_types):
    """
    Extract named entities based on their type (ORG, PERSON, etc.).
    """
    entities = []
    for ent in doc.ents:
        if ent.label_ in entity_types:
            entities.append(ent.text)
    return list(set(entities))

def extract_malware(text):
    """
    Extract malware names from text.
    """
    malware_names = ['Shamoon', 'Stuxnet', 'Emotet']
    detected_malware = [name for name in malware_names if name.lower() in text.lower()]
    return [{'Name': name} for name in detected_malware]

def extract_targeted_entities(doc):
    """
    Extract targeted industries or organizations.
    """
    keywords = ['energy sector', 'finance', 'healthcare']
    detected_entities = [keyword for keyword in keywords if keyword in doc.text.lower()]
    return detected_entities
