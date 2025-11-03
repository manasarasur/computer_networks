import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time, os
from collections import Counter

# Optional: Scapy for live capture
try:
    from scapy.all import sniff, rdpcap, IP
    SCAPY_AVAILABLE = True
except:
    SCAPY_AVAILABLE = False

# ---------- PAGE CONFIG ----------
st.set_page_config(page_title="Network Traffic Analyzer", layout="wide", page_icon="🌐")

# ---------- DARK BLUE THEME ----------
st.markdown("""
<style>
html, body, [class*="stAppViewContainer"], .block-container, .main {
    background-color: #0a0b0e !important;
    color: #e6e6e6 !important;
    font-family: "Poppins", "Segoe UI", Roboto, sans-serif !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f1014 0%, #0a0b0e 100%) !important;
    color: #fafafa !important;
    box-shadow: 2px 0 10px rgba(0, 0, 0, 0.4);
}
section[data-testid="stSidebar"] * { color: #fafafa !important; }
section[data-testid="stSidebar"] button {
    background: linear-gradient(90deg, #2563eb, #3b82f6) !important;
    color: #fff !important;
    border-radius: 6px !important;
    border: none !important;
}
section[data-testid="stSidebar"] button:hover {
    background: linear-gradient(90deg, #3b82f6, #60a5fa) !important;
    box-shadow: 0 0 10px #3da9fc;
}

/* Headings */
h1, h2, h3, h4, h5 {
    color: #3da9fc !important;
    font-weight: 700;
}

/* Metrics visibility */
[data-testid="stMetricLabel"] {
    color: #9ca3af !important;
    font-weight: 500 !important;
    font-size: 16px !important;
}
div[data-testid="stMetricValue"] {
    font-size: 26px !important;
    color: #38bdf8 !important;
}

/* Chart containers */
.stPlotlyChart {
    background-color: #10121a !important;
    border-radius: 14px !important;
    padding: 0.5rem !important;
    box-shadow: 0 0 15px rgba(56,189,248,0.15);
}
.stPlotlyChart:hover {
    transform: scale(1.01);
    transition: transform 0.25s ease-in-out;
}

/* Plot text colors */
svg text {
    fill: #e6e6e6 !important;
}

/* Packet Data Preview Table */
[data-testid="stDataFrame"] {
    background-color: #10121a !important;
    border-radius: 12px !important;
    border: 1px solid #1e293b !important;
    box-shadow: 0 0 15px rgba(56,189,248,0.15);
    padding: 1rem !important;
}
[data-testid="stDataFrame"] thead th {
    background-color: #1b1e24 !important;
    color: #60a5fa !important;
    font-weight: 600 !important;
}
[data-testid="stDataFrame"] tbody td {
    background-color: #10121a !important;
    color: #e6e6e6 !important;
    border-bottom: 0.5px solid #1e293b !important;
}
[data-testid="stDataFrame"] tbody tr:hover td {
    background-color: #1c2029 !important;
    transition: background-color 0.2s ease-in-out;
}

/* Animation */
h1 {
    animation: glowText 3s ease-in-out infinite alternate;
}
@keyframes glowText {
    from { text-shadow: 0 0 4px #3b82f6; }
    to { text-shadow: 0 0 16px #38bdf8; }
}

/* Hide Streamlit header/footer */
footer, header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
st.title("🌐 Intelligent Network Traffic Analyzer & Anomaly Detector")
st.markdown(
    "<p style='color:#9ca3af;'>Analyze, visualize, and detect anomalies in real-time network traffic.</p>",
    unsafe_allow_html=True
)

# ---------- SIDEBAR ----------
# More relevant dark icon for “network analysis”
st.sidebar.image("https://tse2.mm.bing.net/th/id/OIP.OCh6mxnN3QrUSNdNeZdpRwHaE8?w=1600&h=1067&rs=1&pid=ImgDetMain&o=7&rm=3", width=160)
st.sidebar.header("⚙️ Configuration Panel")
mode = st.sidebar.radio("Select Mode", ["Live Capture", "Analyze PCAP File"])
duration = st.sidebar.slider("Capture Duration (seconds)", 5, 30, 10)
st.sidebar.markdown("---")

# ---------- FUNCTIONS ----------
def process_packet(pkt, store):
    ts = time.time()
    try:
        if IP in pkt:
            src, dst, proto = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        else:
            src, dst, proto = "N/A", "N/A", "N/A"
        store.append((ts, str(proto), src, dst, len(pkt)))
    except:
        pass

def capture_live(sec):
    data = []
    if not SCAPY_AVAILABLE:
        st.error("Scapy not available or permission denied. Use PCAP mode.")
        return []
    st.info(f"Capturing live packets for {sec} seconds...")
    sniff(timeout=sec, prn=lambda p: process_packet(p, data))
    return data

def load_pcap(path):
    data = []
    if not os.path.exists(path):
        st.error("File not found.")
        return []
    st.info(f"Loading packets from {path}...")
    for pkt in rdpcap(path):
        process_packet(pkt, data)
    return data

# ---------- CAPTURE / UPLOAD ----------
packets = []
if mode == "Live Capture":
    if st.sidebar.button("▶ Start Capture", use_container_width=True):
        packets = capture_live(duration)
else:
    file = st.sidebar.file_uploader("📁 Upload .pcap File", type=["pcap"])
    if file and st.sidebar.button("📊 Analyze File", use_container_width=True):
        with open("temp.pcap", "wb") as f:
            f.write(file.read())
        packets = load_pcap("temp.pcap")

# ---------- DASHBOARD ----------
if packets:
    df = pd.DataFrame(packets, columns=["Time","Protocol","Source","Destination","Length"])
    df["Second"] = (df["Time"] - df["Time"].min()).astype(int)

    total = len(df)
    uniq = df["Source"].nunique()
    avg = int(df["Length"].mean())

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Packets", total)
    c2.metric("Unique Source IPs", uniq)
    c3.metric("Avg Packet Size", f"{avg} bytes")

    st.markdown("<hr>", unsafe_allow_html=True)

    # ---- FIRST ROW ----
    col1, col2 = st.columns(2)

    # 🟦 PIE CHART - Protocol Distribution (qualitative palette)
    proto = Counter(df["Protocol"])
    proto_df = pd.DataFrame(proto.items(), columns=["Protocol", "Count"])
    fig1 = px.pie(
        proto_df,
        values="Count",
        names="Protocol",
        color_discrete_sequence=px.colors.qualitative.Dark2,
        hole=0.35,
        title="Protocol Distribution"
    )
    fig1.update_traces(
        textinfo="percent+label",
        textfont_size=12,
        marker=dict(line=dict(color="#0a0b0e", width=2))
    )
    fig1.update_layout(
        height=300,
        paper_bgcolor="#10121a",
        font_color="#e6e6e6",
        title_font_color="#60a5fa",
        margin=dict(t=40, b=20, l=20, r=20),
        legend=dict(
            orientation="h",
            y=-0.25,
            x=0.5,
            xanchor="center",
            font=dict(size=11, color="#e6e6e6")
        )
    )
    col1.plotly_chart(fig1, use_container_width=True)

    # 🟦 BAR CHART - Top Source IPs
    src = df["Source"].value_counts().head(5).reset_index()
    src.columns = ["Source", "Count"]
    fig2 = px.bar(
        src, x="Source", y="Count",
        color="Count", color_continuous_scale=px.colors.sequential.Blues,
        title="Top Source IPs"
    )
    fig2.update_layout(height=300, paper_bgcolor="#10121a",
                       font_color="#e6e6e6", title_font_color="#60a5fa",
                       margin=dict(t=40,b=20))
    col2.plotly_chart(fig2, use_container_width=True)

    # ---- SECOND ROW ----
    col3, col4 = st.columns(2)

    # 🟦 LINE CHART - Packet Rate
    rate = df.groupby("Second")["Length"].count().reset_index()
    fig3 = go.Figure()
    fig3.add_trace(go.Scatter(
        x=rate["Second"], y=rate["Length"],
        mode="lines+markers", line=dict(color="#3b82f6", width=3)
    ))
    fig3.update_layout(height=300, paper_bgcolor="#10121a", font_color="#e6e6e6",
                       title="Packet Rate Over Time", title_font_color="#60a5fa",
                       xaxis_title="Seconds", yaxis_title="Packets",
                       margin=dict(t=40,b=20))
    col3.plotly_chart(fig3, use_container_width=True)

    # 🟦 BAR CHART - Top Destination IPs
    dst = df["Destination"].value_counts().head(5).reset_index()
    dst.columns = ["Destination", "Count"]
    fig4 = px.bar(
        dst, x="Destination", y="Count",
        color="Count", color_continuous_scale=px.colors.sequential.Blues,
        title="Top Destination IPs"
    )
    fig4.update_layout(height=300, paper_bgcolor="#10121a", font_color="#e6e6e6",
                       title_font_color="#60a5fa", margin=dict(t=40,b=20))
    col4.plotly_chart(fig4, use_container_width=True)

    # ---- ANOMALY DETECTION ----
    mean = rate["Length"].mean()
    spikes = rate[rate["Length"] > mean * 3]
    st.markdown("<hr>", unsafe_allow_html=True)
    if not spikes.empty:
        st.error(f"⚠️ Anomaly Detected — Sudden traffic spikes at seconds: {list(spikes['Second'])}")
    else:
        st.success("✅ No anomalies detected. Network appears stable.")

    # ---- PACKET DATA TABLE ----
    st.markdown("<hr>", unsafe_allow_html=True)
    st.subheader("📄 Packet Data Preview")
    st.dataframe(df.head(15), use_container_width=True)

else:
    st.info("Use the sidebar to start capture or upload a .pcap file.")
