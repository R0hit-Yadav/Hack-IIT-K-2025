import streamlit as st
import spacy
import utils
from pprint import pformat

nlp = spacy.load("en_core_web_sm")

def extract_threat_intelligence(report_text):
    """
    Extract threat intelligence from a natural language threat report.
    """

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


    doc = nlp(report_text)


    output['IoCs']['IP addresses'] = utils.extract_ip_addresses(report_text)
    output['IoCs']['Domains'] = utils.extract_domains(report_text)


    output['TTPs'] = utils.extract_ttps(report_text)

  
    output['Threat Actor(s)'] = utils.extract_entities(doc, ['ORG', 'PERSON'])

 
    output['Malware'] = utils.extract_malware(report_text)

    output['Targeted Entities'] = utils.extract_targeted_entities(doc)

    return output


def main():
    st.title("Threat Intelligence Extractor")
    st.write("Upload a natural language threat report to extract structured threat intelligence.")


    uploaded_file = st.file_uploader("Upload Threat Report (TXT format)", type="txt")

    if uploaded_file:
    
        report_text = uploaded_file.read().decode("utf-8")

        st.subheader("Uploaded Report")
        st.text_area("Threat Report Content", value=report_text, height=200)

     
        intelligence = extract_threat_intelligence(report_text)

    
        st.subheader("Extracted Threat Intelligence")
        st.json(intelligence)

if __name__ == "__main__":
    main()
