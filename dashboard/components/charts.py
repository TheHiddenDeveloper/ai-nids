"""
Dashboard Charts Components
---------------------------
Contains all Plotly chart generation for the AI-NIDS dashboard.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.geo_utils import GeoLookup

# Initialize Geo Services
geo_lookup = GeoLookup()

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font_color="#aab",
    margin=dict(t=40, b=10, l=10, r=10),
    xaxis=dict(gridcolor="#222", zeroline=False),
    yaxis=dict(gridcolor="#222", zeroline=False),
)

def draw_sankey(df):
    if df.empty or "_src_ip" not in df.columns: return
    links = df.groupby(["_src_ip", "_dst_ip"]).size().reset_index(name="value")
    top_src = links.groupby("_src_ip")["value"].sum().nlargest(6).index
    top_dst = links.groupby("_dst_ip")["value"].sum().nlargest(6).index
    links = links[links["_src_ip"].isin(top_src) & links["_dst_ip"].isin(top_dst)]
    
    all_nodes = list(pd.concat([links["_src_ip"], links["_dst_ip"]]).unique())
    node_map = {n: i for i, n in enumerate(all_nodes)}
    
    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=15, thickness=20, line=dict(color="black", width=0.5), label=all_nodes, color="#10b981"),
        link=dict(source=links["_src_ip"].map(node_map), target=links["_dst_ip"].map(node_map), value=links["value"], color="rgba(16, 185, 129, 0.2)")
    )])
    fig.update_layout(title_text="Network Traffic Flow", font_size=10, **DARK_LAYOUT)
    st.plotly_chart(fig, use_container_width=True, key="sankey_traffic")

def draw_intensity_heatmap(df):
    """Draws an intensity heatmap of alerts over days and hours."""
    if df.empty or "_alerted_at" not in df.columns: return
    tdf = df.copy()
    tdf["dt"] = pd.to_datetime(tdf["_alerted_at"], unit="s", utc=True)
    tdf["hour"] = tdf["dt"].dt.hour
    tdf["day"] = tdf["dt"].dt.day_name()
    
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = tdf.groupby(["day", "hour"]).size().unstack(fill_value=0)
    pivot = pivot.reindex([d for d in days_order if d in pivot.index]).fillna(0)
    
    fig = px.imshow(pivot, labels=dict(x="Hour of Day", y="Day of Week", color="Alerts"), x=pivot.columns, y=pivot.index, color_continuous_scale="Viridis")
    fig.update_layout(**DARK_LAYOUT, height=250)
    st.plotly_chart(fig, use_container_width=True, key="intensity_heatmap")

def draw_threat_map(df):
    """Draws a geographical scatter plot of threat sources."""
    if df.empty or "_src_ip" not in df.columns: return
    
    # Get top 30 source IPs to resolve (limited for performance)
    top_ips = df["_src_ip"].value_counts().head(30).index.tolist()
    
    map_data = []
    for _, row in df.iterrows():
        ip = row.get("_src_ip")
        if not ip: continue
        
        # Use database enrichment if available, fallback to live lookup
        country = row.get("country")
        lat, lon = row.get("lat"), row.get("lon")
        
        if not lat or not lon:
            loc = geo_lookup.get_location(ip)
            if loc:
                lat, lon, country = loc["lat"], loc["lon"], loc["country"]
        
        if lat and lon:
            map_data.append({
                "lat": lat,
                "lon": lon,
                "IP": ip,
                "Location": country or "Unknown",
                "Alerts": 1, # Aggregate later or use pre-aggregated
                "Severity": row.get("severity", "low"),
                "ISP": row.get("isp", "Unknown")
            })
    
    if not map_data:
        st.info("Waiting for geographical threat data...")
        return

    df_map = pd.DataFrame(map_data)
    
    fig = px.scatter_geo(
        df_map, lat="lat", lon="lon",
        size="Alerts", color="Severity",
        hover_name="IP", hover_data=["Location", "Alerts", "ISP"],
        color_continuous_scale="Reds",
        projection="natural earth",
        title="Global Attack Hotspots"
    )
    fig.update_layout(**DARK_LAYOUT, height=450, coloraxis_showscale=False)
    st.plotly_chart(fig, use_container_width=True, key="global_threat_map")

def draw_port_distribution(df):
    """Draws a pie chart of the top targeted ports."""
    if df.empty or "dst_port" not in df.columns: return
    
    port_counts = df["dst_port"].value_counts().head(10).reset_index()
    port_counts.columns = ["Port", "Count"]
    
    fig = px.pie(port_counts, names="Port", values="Count", title="Top Targeted Ports", hole=0.4, color_discrete_sequence=px.colors.sequential.Agalnads)
    fig.update_layout(**DARK_LAYOUT, height=350)
    st.plotly_chart(fig, use_container_width=True, key="port_distribution_pie")
