import json, subprocess, tempfile
from pathlib import Path
import streamlit as st

st.title("Cognitive Security – ZTA Gate Demo (OPA)")

uploaded = st.file_uploader("Upload a session JSON", type=["json","jsonl"])
if uploaded:
    data = json.load(uploaded)
    tmp = Path(tempfile.gettempdir()) / "session.json"
    tmp.write_text(json.dumps(data))

    cmd = ["./opa064","eval","-f","pretty","-i",str(tmp),
           "-d","policy/agent.rego","-d","policy/labels.yaml",
           "data.agent.gate_decisions"]
    out = subprocess.check_output(cmd).decode()
    decisions = json.loads(out)

    st.subheader("Decisions")
    if not decisions:
        st.info("No http_post steps matched.")
    for d in decisions:
        st.markdown(
            f"- **Step {d['step']}** | Zone: `{d['zone']}` | "
            f"Data: `{d['data_class']}` | Risky: `{d['risky']}` | "
            f"**Gate: {d['gate']}**"
        )
