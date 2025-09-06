import json, subprocess
import streamlit as st

LOG_FILE = st.sidebar.text_input("Session log (.jsonl)", "examples/sess_danger.jsonl")
POLICY_REGO = st.sidebar.text_input("Policy (rego)", "policy/agent.rego")
POLICY_DATA = st.sidebar.text_input("Policy data (yaml)", "policy/labels.yaml")

st.title("Cognitive Security Prototype (透明化 × Policy-as-Code)")
st.caption("強制せず、行為列を透明化し、規範に照らして理由つきで提示")

# ログ読込（1セッション/1行）
with open(LOG_FILE) as f:
    sess = json.loads(f.read())

st.subheader(f"行為列（session_id: {sess['session_id']}）")
for step in sess["steps"]:
    st.write(f"t={step['t']} | {step['tool']} → {step.get('args',{})}")

# OPA eval 実行
cmd = [
    "opa","eval","-f","json",
    "-i", LOG_FILE,
    "-d", POLICY_REGO,
    "-d", POLICY_DATA,
    "data.agent.policy.warn"
]
res = subprocess.run(cmd, capture_output=True, text=True)

if res.returncode != 0:
    st.error("OPA eval error")
    st.code(res.stderr)
else:
    try:
        payload = json.loads(res.stdout)
        warns = payload["result"][0]["expressions"][0]["value"]
    except Exception:
        warns = []

    st.subheader("WARN（理由と根拠）")
    if not warns:
        st.success("WARNはありません（OK）")
    else:
        for w in warns:
            rule = w.get("rule")
            reason = w.get("reason")
            refs = w.get("refs", [])
            step = w.get("step", w.get("from"))
            to_step = w.get("to")
            with st.container(border=True):
                st.markdown(f"**{rule}**")
                st.write(f"理由: {reason}")
                if step is not None:
                    st.write(f"関連ステップ: {step}" + (f" → {to_step}" if to_step is not None else ""))
                if refs:
                    st.write("根拠: " + ", ".join(refs))
