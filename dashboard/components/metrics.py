"""
Dashboard Metrics Components
----------------------------
UI components for metric cards and tickers using Material Symbols.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd

SEV_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "low": "#10b981"}

# Material Icons font import string
MATERIAL_FONTS = '<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,1,0" rel="stylesheet" />'

def draw_metric_card(label: str, value: str, icon_name: str, color: str = "#10b981", delta: float = None, invert_delta: bool = False):
    """Draws a responsive metric card using Google Material Symbols instead of emojis."""
    delta_html = ""
    if delta is not None:
        arrow_icon = "trending_up" if delta >= 0 else "trending_down"
        # For alerts, up is usually RED (bad), down is GREEN (good)
        if invert_delta:
            d_color = "#ef4444" if delta > 0 else "#10b981"
            arrow_icon = "trending_up" if delta > 0 else "trending_down"
        else:
            d_color = "#10b981" if delta >= 0 else "#64748b"
        
        delta_html = f"<div style='font-size: 0.85rem; font-weight: 600; color: {d_color}; display:flex; align-items:center;'><span class='material-symbols-rounded' style='font-size: 1rem; margin-right: 2px;'>{arrow_icon}</span> {abs(delta):.1f}%</div>"

    st.markdown(f"""
    {MATERIAL_FONTS}
    <div style="
        background: rgba(30, 41, 59, 0.4);
        padding: 1.25rem;
        border-radius: 12px;
        border-top: 1px solid rgba(255,255,255,0.1);
        border-left: 4px solid {color};
        backdrop-filter: blur(12px);
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        margin-bottom: 1rem;
    ">
        <div style="display: flex; justify-content: space-between; align-items: start;">
            <div style="color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600;">{label}</div>{delta_html}
        </div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 0.5rem;">
            <div style="font-size: 1.7rem; font-weight: 700; color: #f1f5f9; font-family: 'Inter', sans-serif;">{value}</div>
            <span class="material-symbols-rounded" style="font-size: 1.8rem; color: {color}; opacity: 0.8;">{icon_name}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def draw_alert_ticker(df):
    """Draws an animated marquee ticker of recent alerts using Material icons."""
    if df.empty: return
    recent = df.sort_values("_alerted_at", ascending=False).head(8)
    items = []
    
    # Map severity to sensible material icons
    sev_symbols = {"high": "gpp_bad", "medium": "warning", "low": "security"}
    
    for _, row in recent.iterrows():
        sev_raw = row.get("severity", "low")
        sev = sev_raw.upper()
        icon = sev_symbols.get(sev_raw, "info")
        color = SEV_COLOR.get(sev_raw, '#888')
        
        # Robustly handle missing messages
        sig_match = row.get("signature_match")
        if pd.isna(sig_match) or not str(sig_match).strip() or str(sig_match) == "nan":
            msg = f"Anomaly: {row.get('score', 0):.3f}"
        else:
            msg = str(sig_match)
            
        items.append(f"<span style='color:{color}; font-weight:bold; display:inline-flex; align-items:center;'><span class='material-symbols-rounded' style='font-size: 1.2rem; margin-right: 4px;'>{icon}</span>[{sev}]</span> {msg[:50]}...")
    
    ticker_html = f"""
    {MATERIAL_FONTS}
    <div style="background: rgba(15, 23, 42, 0.6); padding: 10px 0; border-top: 1px solid #1e293b; border-bottom: 1px solid #1e293b; margin: 10px 0 25px 0; overflow: hidden; white-space: nowrap; display: flex; align-items: center;">
        <div style="display: inline-block; animation: ticker-scroll 45s linear infinite;">
            {' &nbsp;&nbsp;&nbsp; • &nbsp;&nbsp;&nbsp; '.join(items)} &nbsp;&nbsp;&nbsp; • &nbsp;&nbsp;&nbsp; {' &nbsp;&nbsp;&nbsp; • &nbsp;&nbsp;&nbsp; '.join(items)}
        </div>
    </div>
    <style>
    @keyframes ticker-scroll {{
        0% {{ transform: translateX(0); }}
        100% {{ transform: translateX(-50%); }}
    }}
    </style>
    """
    st.markdown(ticker_html, unsafe_allow_html=True)
