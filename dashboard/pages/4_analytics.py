import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
from dashboard.utils.data import load_from_db
from dashboard.components.charts import draw_port_distribution, DARK_LAYOUT

st.set_page_config(page_title="AI-NIDS | Analytics", page_icon=":material/monitoring:", layout="wide")

st.title("Analytics & ML")

flows_df = load_from_db("flows", limit=5000)
has_flows = not flows_df.empty

col_score, col_perc = st.columns([3, 2])
with col_score:
    st.subheader("ML score distribution")
    if has_flows and "score" in flows_df.columns:
        fig3 = px.histogram(
            flows_df, x="score", nbins=60,
            color_discrete_sequence=["#10b981"],
            labels={"score": "Attack probability score"},
        )
        for thresh, color, name in [
            (0.65, "#facc15", "Low"),
            (0.80, "#f97316", "Medium"),
            (0.92, "#ef4444", "High"),
        ]:
            fig3.add_vline(
                x=thresh, line_dash="dash", line_color=color, line_width=1.5,
                annotation_text=name, annotation_font_color=color,
                annotation_position="top right",
            )
        fig3.update_layout(**DARK_LAYOUT, showlegend=False)
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("Waiting for scored flows.")

with col_perc:
    st.subheader("Score percentiles")
    if has_flows and "score" in flows_df.columns:
        scores = flows_df["score"].dropna()
        p_vals = [50, 75, 90, 95, 99]
        p_data = {f"p{p}": round(float(scores.quantile(p/100)), 4) for p in p_vals}
        p_df = pd.DataFrame({"Percentile": list(p_data.keys()), "Score": list(p_data.values())})
        st.dataframe(p_df, use_container_width=True, hide_index=True)
    else:
        st.info("N/A")
        
st.markdown("---")
st.subheader("Port Vulnerability Distribution")
draw_port_distribution(flows_df)

st.markdown("---")
st.subheader("AI Engine Specifications")
st.write("""
- **Algorithms:** Random Forest (Supervised) + Deep Autoencoder (Unsupervised)
- **Model Weighting:** 0.5 RF / 0.5 AE
- **Baseline Data:** CICIDS2017 Deep Research Subset
- **Feature Schema:** 20-Factor Network Packet Analysis
""")
