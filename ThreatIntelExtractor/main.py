import streamlit as st
import spacy
import utils
import json
import matplotlib.pyplot as plt

# Load SpaCy NLP model
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

def visualize_data(output):
    """
    Create visualizations for the extracted threat intelligence data.
    """
    st.subheader("Visualizations")

    # IoC Visualization
    st.markdown("### Indicators of Compromise (IoCs)")
    ioc_counts = {
        'IP Addresses': len(output['IoCs']['IP addresses']),
        'Domains': len(output['IoCs']['Domains']),
    }

    fig, ax = plt.subplots()
    ax.bar(ioc_counts.keys(), ioc_counts.values(), color=['#1f77b4', '#ff7f0e'])
    ax.set_ylabel("Count")
    ax.set_title("IoCs (IP Addresses vs Domains)")
    st.pyplot(fig)

    # TTP Visualization
    st.markdown("### Tactics and Techniques")
    tactic_count = len(output['TTPs']['Tactics'])
    technique_count = len(output['TTPs']['Techniques'])

    fig, ax = plt.subplots()
    ax.bar(['Tactics', 'Techniques'], [tactic_count, technique_count], color=['#2ca02c', '#d62728'])
    ax.set_ylabel("Count")
    ax.set_title("TTPs (Tactics vs Techniques)")
    st.pyplot(fig)

    # Malware Count
    st.markdown("### Malware")
    malware_count = len(output['Malware'])

    fig, ax = plt.subplots()
    ax.bar(['Malware'], [malware_count], color=['#9467bd'])
    ax.set_ylabel("Count")
    ax.set_title("Malware Count")
    st.pyplot(fig)

def calculate_threat_severity(output):
    """
    Calculate a threat severity score based on extracted intelligence.
    """
    score = 0

    # Assign points for IoCs
    score += len(output['IoCs']['IP addresses']) * 5
    score += len(output['IoCs']['Domains']) * 5

    # Assign points for TTPs
    score += len(output['TTPs']['Tactics']) * 10
    score += len(output['TTPs']['Techniques']) * 10

    # Assign points for Malware
    score += len(output['Malware']) * 15

    # Assign points for Targeted Entities
    if output['Targeted Entities']:
        score += 20

    # Determine severity level
    if score >= 50:
        severity = "High"
    elif score >= 20:
        severity = "Medium"
    else:
        severity = "Low"

    return severity, score


# Streamlit UI
def main():
   
    st.title("Threat Intelligence Extractor")
    st.markdown("Extract structured threat intelligence from natural language threat reports.")

    # Sidebar for themes
    st.sidebar.header("Menu")

   
    # Sidebar for bonus features
    st.sidebar.header("Bonus Features")
    report_type = st.sidebar.selectbox("Choose a Report Type", ["Upload Your Report", "Use Example Reports"])
    manage_malware = st.sidebar.selectbox("Manage Malware", ["None", "Add Malware", "Remove Malware"])

    # Preloaded example reports
    example_reports = {
        "Healthcare Attack": """
            The Conti group has been responsible for a new ransomware attack targeting the healthcare sector. 
            The attack utilized the Ryuk malware, which was delivered via a phishing email containing malicious links. 
            The ransomware communicates with IP address 192.168.0.101 and domain attack-server.net. 
            This campaign caused significant disruption to hospitals and medical institutions.
        """,
        "Energy Sector Attack": """
            A new campaign launched by APT33 targets energy sector organizations. The attack uses Shamoon malware to 
            destroy critical infrastructure. Observations indicate communication with IP 203.0.113.10 and domain energy-hack.com.
        """
    }

    # Input: Upload or Use Example
    report_text = ""
    
    if report_type == "Upload Your Report":
        uploaded_file = st.file_uploader("Upload a Threat Report (.txt format)", type="txt")
        if uploaded_file:
            report_text = uploaded_file.read().decode("utf-8")
    else:
        selected_example = st.selectbox("Select an Example Report", list(example_reports.keys()))
        report_text = example_reports[selected_example]

    # Manage Malware: Add or Remove
    if manage_malware == "Add Malware":
        custom_malware = st.text_input("Add Custom Malware (comma-separated)")
        if st.button("Add Malware"):
            utils.add_custom_malware(custom_malware.split(","))
            st.success(f"Added malware: {custom_malware}")
    elif manage_malware == "Remove Malware":
        malware_to_remove = st.multiselect("Select Malware to Remove", utils.malware_names)
        if st.button("Remove Malware"):
            utils.remove_custom_malware(malware_to_remove)
            st.success(f"Removed malware: {', '.join(malware_to_remove)}")

    if report_text:
        # Display uploaded/selected report
        st.subheader("Threat Report")
        st.text_area("Report Content", value=report_text, height=200)

        # Extract intelligence
        intelligence = extract_threat_intelligence(report_text)

        # Display the extracted intelligence
        st.subheader("Extracted Threat Intelligence")
        st.json(intelligence)

        # Collapsible Sections
        with st.expander("Visualizations"):
            visualize_data(intelligence)

        with st.expander("Threat Severity"):
            severity, score = calculate_threat_severity(intelligence)
            st.markdown(f"**Severity Level:** {severity}")
            st.markdown(f"**Score:** {score}")

            # Progress bar
            st.progress(min(score, 100) / 100)

        # Downloadable JSON
        st.download_button(
            label="Download JSON",
            data=json.dumps(intelligence, indent=4),
            file_name="threat_intelligence.json",
            mime="application/json"
        )

if __name__ == "__main__":
    main()
