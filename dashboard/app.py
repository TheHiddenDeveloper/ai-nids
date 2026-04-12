"""
AI-NIDS Live Dashboard Entry Point
----------------------------------
Modular Multipage Application configuration.
"""

import streamlit as st

st.set_page_config(page_title="AI-NIDS Central", layout="wide", initial_sidebar_state="expanded")

# Define the navigation structure using modern multipage routing
pg = st.navigation(
    {
        "Dashboards": [
            st.Page("pages/1_overview.py", title="Overview", icon=":material/dashboard:", default=True),
            st.Page("pages/2_alerts.py", title="Alerts Explorer", icon=":material/policy:"),
            st.Page("pages/3_incidents.py", title="Active Incidents", icon=":material/local_fire_department:"),
            st.Page("pages/4_analytics.py", title="Analytics & ML", icon=":material/monitoring:")
        ],
        "Configuration": [
            st.Page("pages/5_settings.py", title="Settings", icon=":material/settings:")
        ]
    }
)

# Apply global custom CSS to override default styling for all pages
st.markdown("""
<style>
    /* Global Background and Text */
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
        font-family: 'Inter', sans-serif;
    }
    
    /* Metrics Overrides */
    [data-testid="stMetricValue"]  { font-size: 1.8rem !important; font-weight: 700; color: #f8fafc; }
    [data-testid="stMetricLabel"]  { font-size: 0.85rem !important; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }

    div[data-testid="column"] { padding: 0 8px; }
    
    /* Table styling */
    .stDataFrame { border: 1px solid rgba(255,255,255,0.05); border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# Run the navigation router
pg.run()
