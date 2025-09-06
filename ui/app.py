import json, subprocess, glob
import streamlit as st

st.set_page_config(page_title="Cognitive Security Prototype", layout="wide")

# --- サイドバー：ログ選択 ---
EXAMPLES = sorted(glob.glob("examples/*.jsonl"))
DEFAULT = "examples/sess_danger.jsonl" if "examples/sess_danger.jsonl" in EXAMPLES else (EXAMPLES[0] if EXAMPLES else "")
LOG_FILE = st.sidebar.selectbox("Session log (.jsonl)", EXAMPLES, index=EXAMPLES.index(DEFAULT) if DEFAULT in EXAMPLES else 0)
POLICY_REGO = "policy/agent.rego"
POLICY_DATA = "policy/labels.yaml"

st.title("Cognitive Security Prototype（透明化 × Policy-as-Code）")
st.caption("強制せず、行為列を透明化し、規範に照らして理由つきで提示（認知的自律を尊重）")

# --- セッション読み込み ---
with open(LOG_FILE) as f:
    sess = json.loads(f.read())
steps = sess.get("steps", [])

# --- OPA評価 ---
cmd = [
    "opa","eval","-f","json",
    "-i", LOG_FILE,
    "-d", POLICY_REGO,
    "-d", POLICY_DATA,
    "data.agent.policy.warn"
]
res = subprocess.run(cmd, capture_output=True, text=True)
warns = []
if res.returncode == 0:
    try:
        payload = json.loads(res.stdout)
        warns = payload["result"][0]["expressions"][0]["value"] or []
    except Exception:
        warns = []
else:
    st.error("OPA eval error"); st.code(res.stderr)

# --- 要約バッジ ---
sev_order = {"high":0,"medium":1,"low":2,"info":3}
def sev(v): return (v or "").lower()

counts = {"high":0,"medium":0,"low":0,"info":0}
for w in warns:
    counts[sev(w.get("severity"))] = counts.get(sev(w.get("severity")),0) + 1

cols = st.columns(4)
cols[0].metric("HIGH",   counts["high"])
cols[1].metric("MEDIUM", counts["medium"])
cols[2].metric("LOW",    counts["low"])
cols[3].metric("INFO",   counts["info"])

st.divider()

# --- 2カラム：左=タイムライン / 右=WARN ---
left, right = st.columns([1.1,1])

# ===== 左：タイムライン =====
with left:
    st.subheader(f"行為列（session_id: {sess.get('session_id')}）")
    tool_emoji = {
        "web_search":"🔎", "http_get":"⬇️", "http_post":"⬆️",
        "extract_pii":"🧩", "file_download":"📥", "tool_execute":"🛠️"
    }
    selected_steps = st.session_state.get("selected_steps", set())

    for idx, step in enumerate(steps, start=1):
        icon = tool_emoji.get(step.get("tool"), "•")
        is_selected = idx in selected_steps
        style = "background-color:#fffbe6;border-left:4px solid #f59e0b;padding:6px 10px;border-radius:6px;" if is_selected else "padding:6px 10px;border-left:4px solid #e5e7eb;border-radius:6px;"
        st.markdown(f"<div style='{style}'>"
                    f"<b>Step {idx}</b> {icon} <code>{step.get('tool')}</code>"
                    f"<br><span style='opacity:0.75'>{step.get('args',{})}</span>"
                    f"</div>", unsafe_allow_html=True)

# ===== 右：WARN（フィルタ＋カード） =====
with right:
    st.subheader("WARN（理由・根拠）")

    # フィルタUI
    with st.expander("フィルタ"):
        sev_opts = ["high","medium","low","info"]
        sel_sev = st.multiselect("Severity", options=sev_opts, default=[s for s,c in counts.items() if c>0] or sev_opts)
        rule_names = sorted(set(w.get("rule") for w in warns))
        sel_rules = st.multiselect("Rule", options=rule_names, default=rule_names)

    # 並べ替え＆フィルタ
    warns_sorted = sorted(warns, key=lambda w: sev_order.get(sev(w.get("severity")), 99))
    warns_view = [w for w in warns_sorted if (sev(w.get("severity")) in sel_sev and w.get("rule") in sel_rules)]

    if not warns_view:
        st.success("WARNはありません（OK もしくはフィルタにより非表示）")
    else:
        new_selected = set()
        for w in warns_view:
            r = w.get("rule"); reason = w.get("reason")
            severity = sev(w.get("severity"))
            refs = w.get("refs", [])
            step = w.get("step", w.get("from"))
            to_step = w.get("to")
            # 色分け
            header = f"[{severity.upper()}] {r}"
            body = []
            body.append(f"理由: {reason}")
            if step is not None:
                body.append("関連ステップ: " + (f"{step} → {to_step}" if to_step is not None else f"{step}"))
                # タイムライン側ハイライト対象に追加
                new_selected.add(int(step)) if isinstance(step,int) else None
                if isinstance(to_step,int): new_selected.add(int(to_step))
            if refs:
                body.append("根拠: " + ", ".join(refs))
            body_txt = "\n".join(body)

            if severity == "high":
                st.error(header); st.write(body_txt)
            elif severity == "medium":
                st.warning(header); st.write(body_txt)
            else:
                st.info(header); st.write(body_txt)

        # ハイライト選択状態を更新
        st.session_state["selected_steps"] = new_selected

# フッター的にファイル名表示
st.caption(f"Loaded: {LOG_FILE}")
