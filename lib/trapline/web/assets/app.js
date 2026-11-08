/* Trapline editor — no build step, no framework. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) n.append(kid.nodeType ? kid : String(kid));
    return n;
  };
  const debounce = (fn, ms) => {
    let t;
    const d = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
    d.cancel = () => clearTimeout(t);
    return d;
  };
  const plural = (n, word) => `${n} ${n === 1 ? word : `${word}s`}`;

  async function api(path, { method = "GET", body } = {}) {
    const res = await fetch(path, {
      method,
      headers: { "content-type": "application/json", "x-trapline": "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* no body */ }
    if (!res.ok) {
      const err = new Error(data.error || `Error ${res.status}`);
      err.data = data;
      throw err;
    }
    return data;
  }

  const MODES = {
    ruby: "ruby", python: "python", javascript: "javascript", typescript: "text/typescript",
    java: "text/x-java", go: "go", csharp: "text/x-csharp", kotlin: "text/x-kotlin", scala: "text/x-scala",
    c: "text/x-csrc", cpp: "text/x-c++src", rust: "rust", bash: "shell", yaml: "yaml",
    json: "application/json", dockerfile: "shell", terraform: null, generic: null, regex: null,
  };

  function makeEditor(host, { mode, gutter = false } = {}) {
    if (window.CodeMirror) {
      const cm = window.CodeMirror(host, {
        value: "", mode, lineNumbers: true, tabSize: 2, indentUnit: 2, lineWrapping: false,
        gutters: gutter ? ["ann-gutter", "CodeMirror-linenumbers"] : ["CodeMirror-linenumbers"],
        extraKeys: { Tab: (c) => (c.somethingSelected() ? c.execCommand("indentMore") : c.execCommand("insertSoftTab")), "Shift-Tab": "indentLess" },
      });
      let marks = [];
      let lineClasses = [];
      let badges = [];
      return {
        get: () => cm.getValue(),
        set: (v) => { cm.setValue(v || ""); cm.clearHistory(); },
        onChange: (fn) => cm.on("change", (_c, ch) => { if (ch.origin !== "setValue") fn(); }),
        setMode: (m) => cm.setOption("mode", m),
        clearMarks() {
          marks.forEach((m) => m.clear());
          lineClasses.forEach(([l, where, cls]) => cm.removeLineClass(l, where, cls));
          marks = []; lineClasses = [];
          if (gutter) cm.clearGutter("ann-gutter");
        },
        markRange(from, to, cls) {
          marks.push(cm.markText({ line: from.line - 1, ch: Math.max(0, from.col - 1) }, { line: to.line - 1, ch: Math.max(0, to.col - 1) }, { className: cls }));
        },
        markLine(line, cls) {
          if (line < 1 || line > cm.lineCount()) return;
          const h = cm.addLineClass(line - 1, "background", cls);
          lineClasses.push([h, "background", cls]);
        },
        gutterMark(line, node) {
          if (gutter && line >= 1 && line <= cm.lineCount()) cm.setGutterMarker(line - 1, "ann-gutter", node);
        },
        focusLine(line) {
          cm.focus();
          cm.setCursor({ line: line - 1, ch: 0 });
          cm.scrollIntoView({ line: line - 1, ch: 0 }, 80);
          const h = cm.addLineClass(line - 1, "background", "hl-flash");
          setTimeout(() => cm.removeLineClass(h, "background", "hl-flash"), 900);
        },
        refresh: () => cm.refresh(),
        hasFocus: () => cm.hasFocus(),
        // Replaces the whole text as one undoable edit, keeping cursor and scroll.
        replaceAll(text) {
          const scroll = cm.getScrollInfo();
          const cursor = cm.getCursor();
          const last = cm.lastLine();
          cm.replaceRange(text, { line: 0, ch: 0 }, { line: last, ch: cm.getLine(last).length }, "+expect");
          cm.setCursor(cursor);
          cm.scrollTo(scroll.left, scroll.top);
        },
        onGutterClick: (fn) => cm.on("gutterClick", (_c, line) => fn(line + 1)),
        // Shows each range as `node` without touching the text, so the file and
        // its line numbers stay exactly as the engine sees them.
        setBadges(list) {
          cm.operation(() => {
            badges.forEach((m) => m.clear());
            badges = list.map(({ line, from, to, node }) =>
              cm.markText({ line: line - 1, ch: from }, { line: line - 1, ch: to }, { replacedWith: node, atomic: true, handleMouseEvents: true }));
          });
        },
        setCursor(line, ch) { cm.focus(); cm.setCursor({ line: line - 1, ch }); },
        onCursor: (fn) => cm.on("cursorActivity", () => fn(cm.getCursor().line + 1)),
      };
    }
    const ta = el("textarea", { class: "fallback", spellcheck: "false" });
    host.append(ta);
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Tab") {
        e.preventDefault();
        const s = ta.selectionStart;
        ta.setRangeText("  ", s, ta.selectionEnd, "end");
        ta.dispatchEvent(new Event("input"));
      }
    });
    return {
      get: () => ta.value,
      set: (v) => { ta.value = v || ""; },
      onChange: (fn) => ta.addEventListener("input", fn),
      setMode() {}, clearMarks() {}, markRange() {}, markLine() {}, gutterMark() {},
      focusLine(line) {
        const idx = ta.value.split("\n").slice(0, line - 1).join("\n").length + (line > 1 ? 1 : 0);
        ta.focus(); ta.setSelectionRange(idx, idx);
      },
      refresh() {}, hasFocus: () => document.activeElement === ta,
      replaceAll(text) { ta.value = text; ta.dispatchEvent(new Event("input")); },
      onGutterClick() {}, setBadges() {}, setCursor() {}, onCursor() {},
    };
  }

  const S = {
    info: null, rules: [], slug: null, dirty: false, fields: null, readOnly: false,
    testLang: null, testLangManual: false, annId: null, cve: null,
  };
  const MODE_LABELS = { search: "Search mode", taint: "Taint mode (data flow)", join: "Join mode", extract: "Extract mode" };

  const yamlEd = makeEditor($("#yaml-editor"), { mode: "yaml" });
  const testEd = makeEditor($("#test-editor"), { mode: "ruby", gutter: true });
  const form = $("#fields");

  let toastTimer;
  function toast(msg, kind = "info") {
    const t = $("#toast");
    t.textContent = msg;
    t.className = `toast ${kind === "error" || kind === "success" ? kind : ""}`;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, kind === "error" ? 6000 : 2600);
  }

  function showDialog(d) {
    d.returnValue = "";
    d.showModal();
    return new Promise((resolve) => d.addEventListener("close", () => resolve(d.returnValue === "ok"), { once: true }));
  }

  function confirmDialog(title, text, okLabel) {
    $("#confirm-title").textContent = title;
    $("#confirm-text").textContent = text;
    $("#confirm-ok").textContent = okLabel;
    return showDialog($("#dlg-confirm"));
  }

  function setDirty(v) {
    S.dirty = v;
    const st = $("#doc-state");
    st.textContent = v ? (S.slug ? "Unsaved changes" : "Not saved yet") : (S.slug ? "Saved" : "");
    st.classList.toggle("dirty", v);
  }

  function docName() {
    if (S.slug) return `${S.slug}.yaml`;
    return S.fields?.id ? `${S.fields.id} (new)` : "Untitled rule";
  }

  function setDocName() {
    $("#doc-name").textContent = docName();
    $("#btn-delete").hidden = !S.slug || S.readOnly;
    $("#btn-save").disabled = S.readOnly;
    renderList();
  }

  function fillSelect(select, items, { value, blank } = {}) {
    select.replaceChildren(...(blank ? [el("option", { value: "" }, blank)] : []),
      ...items.map((i) => el("option", { value: i.key }, i.name)));
    if (value) select.value = value;
  }

  function renderList() {
    const q = $("#filter").value.trim().toLowerCase();
    const list = $("#rule-list");
    const rules = S.rules.filter((r) => !q || [r.slug, r.id, ...(r.cve || []), ...(r.cwe || [])].join(" ").toLowerCase().includes(q));
    if (!S.rules.length) {
      list.replaceChildren(el("li", { class: "empty" }, "No saved rules yet. Create a new one or generate one from a CVE."));
      return;
    }
    if (!rules.length) {
      list.replaceChildren(el("li", { class: "empty" }, "Nothing matches the filter."));
      return;
    }
    list.replaceChildren(...rules.map((r) => el("li", {},
      el("button", { type: "button", "aria-current": r.slug === S.slug ? "true" : "false", onclick: () => openRule(r.slug) },
        el("span", { class: "rl-id" }, r.slug),
        r.error
          ? el("span", { class: "rl-meta rl-err" }, "Invalid YAML")
          : el("span", { class: "rl-meta" },
            el("span", { class: `rl-sev sev-${r.severity}` }, r.severity || ""),
            el("span", {}, (r.languages || []).join(", ")),
            (r.cve || [])[0] ? el("span", {}, r.cve[0]) : null,
            r.has_test ? null : el("span", {}, "no test"))))));
  }

  async function loadRules() {
    const data = await api("api/rules");
    S.rules = data.rules;
    S.readOnly = data.read_only;
    $("#rules-path").textContent = `Folder: ${data.path}`;
    renderList();
  }

  async function guardDirty() {
    if (!S.dirty) return true;
    return confirmDialog("Discard changes?", "The current rule has changes that have not been saved yet.", "Discard");
  }

  async function openRule(slug) {
    if (slug === S.slug) return;
    if (!(await guardDirty())) return;
    try {
      const r = await api(`api/rules/${slug}`);
      loadDocument({ slug, yaml: r.yaml, test_code: r.test_code || "", language: r.test_language });
    } catch (e) { toast(e.message, "error"); }
  }

  function loadDocument({ slug = null, yaml, test_code, language }) {
    S.slug = slug;
    S.annId = null;
    S.testLangManual = !!language;
    yamlEd.set(yaml);
    testEd.set(test_code || "");
    testEd.clearMarks();
    revealedLine = null;
    renderBadges();
    if (language) setTestLang(language);
    setDirty(!slug);
    validateNow().then(() => { setDocName(); runNow(); });
  }

  let validateSeq = 0;
  async function validateNow() {
    const seq = ++validateSeq;
    try {
      const res = await api("api/validate", { method: "POST", body: { yaml: yamlEd.get() } });
      if (seq !== validateSeq) return;
      renderIssues(res.issues || []);
      if (res.fields) {
        if (S.annId && res.fields.id && res.fields.id !== S.annId) renameAnnotations(S.annId, res.fields.id);
        const idChanged = res.fields.id !== S.fields?.id;
        if (res.fields.id) S.annId = res.fields.id;
        S.fields = res.fields;
        if (idChanged) renderBadges();
        fillForm(res.fields);
        if (!S.testLangManual && res.fields.languages?.[0]) setTestLang(res.fields.languages[0]);
        $("#mode").textContent = MODE_LABELS[res.fields.mode] || "";
        $("#doc-name").textContent = docName();
      }
    } catch (e) { renderIssues([{ level: "error", path: "", message: e.message }]); }
  }
  const validateSoon = debounce(validateNow, 350);

  function renderIssues(issues) {
    const box = $("#issues");
    yamlEd.clearMarks();
    issues.forEach((i) => {
      const m = /line (\d+)/.exec(i.message);
      if (i.level === "error" && m && !i.path) yamlEd.markLine(Number(m[1]), "err-line");
    });
    const relevant = issues.filter((i) => i.level !== "info");
    if (relevant.length) box.replaceChildren(...relevant.map(issueRow));
    else box.replaceChildren(el("p", { class: "ok" }, "Valid structure."), ...issues.slice(0, 2).map(issueRow));
  }

  function issueRow(i) {
    const label = { error: "Error", warning: "Warning", info: "Tip" }[i.level] || i.level;
    return el("div", { class: `issue issue-${i.level}` },
      el("b", {}, label),
      el("span", {}, i.message, i.path ? el("span", { class: "issue-path" }, `  ${i.path}`) : null));
  }

  function fillForm(f) {
    const set = (name, v) => {
      const input = form.elements[name];
      if (input && document.activeElement !== input) input.value = v ?? "";
    };
    set("id", f.id);
    set("severity", f.severity);
    set("languages", (f.languages || []).join(", "));
    set("message", f.message);
    set("cwe", (f.metadata?.cwe || []).join(", "));
    set("cve", (f.metadata?.cve || []).join(", "));
    set("confidence", f.metadata?.confidence || "");
    set("references", (f.metadata?.references || []).join("\n"));
    const sum = [f.severity, (f.languages || []).join(", "), ...(f.metadata?.cve || []).slice(0, 1), ...(f.metadata?.cwe || []).slice(0, 1).map((c) => c.split(":")[0])].filter(Boolean);
    $("#details-summary").textContent = sum.join(", ");
  }

  function formFields() {
    const v = (n) => form.elements[n].value;
    return {
      id: v("id"), severity: v("severity"), languages: v("languages"), message: v("message"),
      metadata: { cwe: v("cwe"), cve: v("cve"), confidence: v("confidence"), references: v("references") },
    };
  }

  const mergeSoon = debounce(async () => {
    try {
      const res = await api("api/merge", { method: "POST", body: { yaml: yamlEd.get(), fields: formFields() } });
      yamlEd.set(res.yaml);
      setDirty(true);
      await validateNow();
      runSoon();
    } catch (e) { toast(`Fix the YAML before using the form: ${e.message}`, "error"); }
  }, 400);

  function setTestLang(lang) {
    S.testLang = lang;
    $("#test-lang").value = lang;
    testEd.setMode(MODES[lang] ?? null);
  }

  let runSeq = 0;
  // Only manual runs (Run button, Ctrl+Enter) toast: "Run on edit" would
  // otherwise pop one on every pause in typing.
  async function runNow({ manual = false } = {}) {
    if (!S.info?.engine) {
      const msg = "No engine found. Install opengrep or semgrep and restart Trapline to run rules.";
      showRunStatus(statusCard("fail", "Cannot run", msg));
      $("#results").replaceChildren();
      if (manual) toast(msg, "error");
      return;
    }
    const seq = ++runSeq;
    setRunning(true);
    try {
      const res = await api("api/run", { method: "POST", body: { yaml: yamlEd.get(), code: testEd.get(), language: S.testLang } });
      if (seq === runSeq) {
        const outcome = renderResults(res);
        if (manual) toast(outcome.title, { fail: "error", pass: "success" }[outcome.state] || "info");
      }
    } catch (e) {
      if (seq === runSeq) {
        testEd.clearMarks(); // stale ✓/✕ from a previous run would be misleading
        showRunStatus(statusCard("fail", "Run failed", e.message));
        $("#results").replaceChildren();
        if (manual) toast(`Run failed: ${e.message}`, "error");
      }
    } finally {
      if (seq === runSeq) { setRunning(false); flashResults(); }
    }
  }

  // Feedback even when the results do not change (a manual Run after "Run on edit").
  function setRunning(on) {
    const btn = $("#btn-run");
    btn.disabled = on;
    btn.textContent = on ? "Running…" : "Run";
    for (const box of [$("#run-status"), $("#results")]) {
      box.classList.toggle("running", on);
      box.setAttribute("aria-busy", on ? "true" : "false");
    }
  }

  function flashResults() {
    const box = $("#run-status");
    box.classList.remove("fresh");
    void box.offsetWidth; // restart the animation
    box.classList.add("fresh");
  }

  function showRunStatus(card) {
    $("#run-status").replaceChildren(card);
  }
  const runSoon = debounce(() => { if ($("#auto-run").checked) runNow(); }, 800);

  const ICON = { pass: "✓", fail: "✕", todo: "·", hit: "!" };
  const resultKind = (r) => (r.kind === "unexpected" ? "fail" : r.status);

  const ANN_RE = /(#|\/\/|\/\*|<!--|--)\s*(ruleid|ok|todoruleid|todook)\s*:\s*([A-Za-z0-9._\-, ]+)/;

  const annotationOnly = (line) => {
    const m = ANN_RE.exec(line || "");
    return m && !line.slice(0, m.index).trim() ? m : null;
  };
  const withoutAnnotation = (line) => {
    const m = ANN_RE.exec(line || "");
    return (m ? line.slice(0, m.index) : line || "").trim();
  };
  const commentPrefix = () => S.info?.languages?.find((l) => l.key === S.testLang)?.comment || "#";
  const ruleId = () => S.fields?.id || "my-rule";

  // Annotation for 0-based line i: a comment-only line right above it, or a
  // trailing comment on the line itself.
  function annotationFor(lines, i) {
    const above = i > 0 && annotationOnly(lines[i - 1]);
    if (above) return { index: i - 1, kind: above[2] };
    const m = ANN_RE.exec(lines[i] || "");
    return m ? { index: i, kind: m[2], inline: true } : null;
  }

  function addAnnotation(lines, i, kind) {
    const indent = (lines[i] || "").match(/^\s*/)[0];
    lines.splice(i, 0, `${indent}${commentPrefix()} ${kind}: ${ruleId()}`);
  }

  function setAnnotationKind(lines, index, kind) {
    lines[index] = lines[index].replace(/\b(?:todoruleid|todook|ruleid|ok)(\s*:)/, `${kind}$1`);
  }

  function removeAnnotation(lines, index) {
    const m = ANN_RE.exec(lines[index] || "");
    if (!m) return;
    if (annotationOnly(lines[index])) lines.splice(index, 1);
    else lines[index] = lines[index].slice(0, m.index).trimEnd();
  }

  function editTestCode(fn) {
    const lines = testEd.get().split("\n");
    if (fn(lines) === false) return;
    testEd.replaceAll(lines.join("\n"));
    runSoon.cancel();
    runNow();
  }

  function cycleExpectation(lineNo) {
    editTestCode((lines) => {
      let i = lineNo - 1;
      while (i < lines.length && annotationOnly(lines[i])) i++; // clicked the comment: act on its code line
      if (i >= lines.length || !lines[i].trim()) {
        toast("Click next to a line of code to mark what the rule should do with it.");
        return false;
      }
      const a = annotationFor(lines, i);
      if (!a) addAnnotation(lines, i, "ruleid");
      else if (a.kind === "ruleid" || a.kind === "todoruleid") setAnnotationKind(lines, a.index, "ok");
      else removeAnnotation(lines, a.index);
    });
  }

  const BADGES = {
    ruleid: ["must match", "pass"], ok: ["must not match", "fail"],
    todoruleid: ["should match (todo)", "todo"], todook: ["should not match (todo)", "todo"],
  };
  let revealedLine = null; // annotation shown as raw text while the cursor is on it

  function renderBadges() {
    if ($("#raw-ann").checked) return testEd.setBadges([]);
    const badges = [];
    testEd.get().split("\n").forEach((line, i) => {
      const m = ANN_RE.exec(line);
      if (!m || i + 1 === revealedLine) return;
      const end = m.index + m[0].length;
      const to = /^\s*(\*\/|-->)?\s*$/.test(line.slice(end)) ? line.length : end;
      badges.push({ line: i + 1, from: m.index, to, node: badge(m[2], m[3], line.slice(m.index, to).trim(), i + 1, !!annotationOnly(line)) });
    });
    testEd.setBadges(badges);
  }

  function badge(kind, ids, raw, lineNo, above) {
    const [label, cls] = BADGES[kind];
    const others = ids.split(",").map((id) => id.trim()).filter((id) => id && id !== ruleId());
    return el("span", {
      class: `ann-badge ann-badge-${cls}`, title: `${raw}\nClick to edit the comment`, "aria-label": `${label}${others.length ? ` for ${others.join(", ")}` : ""}`,
      onmousedown: (e) => { e.preventDefault(); revealLine(lineNo); },
    }, `${above ? "↓ " : ""}${label}`, others.length ? el("span", { class: "ann-badge-ids" }, others.join(", ")) : null);
  }

  function revealLine(lineNo) {
    revealedLine = lineNo;
    renderBadges();
    const line = testEd.get().split("\n")[lineNo - 1] || "";
    testEd.setCursor(lineNo, line.length);
  }

  function renameAnnotations(from, to) {
    const text = testEd.get();
    const next = text.split("\n").map((line) => {
      const m = ANN_RE.exec(line);
      if (!m) return line;
      const start = m.index + m[0].length - m[3].length;
      const ids = m[3].replace(/[^,\s]+/g, (id) => (id === from ? to : id));
      return line.slice(0, start) + ids + line.slice(m.index + m[0].length);
    }).join("\n");
    if (next !== text) testEd.replaceAll(next);
  }

  // Line numbers come from the last run: insert bottom-up so they stay valid.
  function acceptFindings(lineNos, kind) {
    editTestCode((lines) => {
      [...new Set(lineNos)].sort((a, b) => b - a).forEach((l) => addAnnotation(lines, l - 1, kind));
    });
  }

  function actionsFor(r) {
    const act = (label, title, fn, cls = "") => el("button", { type: "button", class: `res-act ${cls}`, title, onclick: fn }, label);
    if (r.kind === "unexpected" || r.kind === "finding") {
      return [act("Expected", "The rule is right: keep this finding as a test (ruleid)", () => acceptFindings([r.line], "ruleid"), "pass"),
              act("False positive", "The rule should not match here (ok)", () => acceptFindings([r.line], "ok"), "fail")];
    }
    if (r.status !== "fail") return [];
    if (r.kind === "ok") {
      return [act("Expect it", "This finding is correct: change ok to ruleid", () => editTestCode((lines) => setAnnotationKind(lines, r.annotation_line - 1, "ruleid")))];
    }
    return [act("Remove", "Remove this expectation", () => editTestCode((lines) => removeAnnotation(lines, r.annotation_line - 1)))];
  }

  function resultRow(r, code, kind, reason) {
    return el("li", {},
      el("button", { type: "button", class: "res-main", onclick: () => testEd.focusLine(r.line) },
        el("span", { class: `ann ann-${kind}` }, ICON[kind] || "·"),
        el("span", { class: "res-line" }, `line ${r.line}`),
        el("span", { class: "res-code" }, code, reason ? el("span", { class: "res-reason" }, reason) : null)),
      el("span", { class: "res-acts" }, ...actionsFor(r)));
  }

  function acceptAllBar(lineNos) {
    if (!lineNos.length) return null;
    return el("div", { class: "res-bar" },
      el("span", {}, `${plural(lineNos.length, "finding")} ${lineNos.length === 1 ? "has" : "have"} no expectation yet.`),
      el("button", { type: "button", class: "res-act pass", onclick: () => acceptFindings(lineNos, "ruleid") },
        lineNos.length === 1 ? "Accept as expected" : "Accept all as expected"));
  }

  function statusCard(state, title, sub) {
    return el("div", { class: `status-card status-${state}`, role: state === "fail" ? "alert" : "status" },
      el("span", { class: "status-icon", "aria-hidden": "true" }, state === "pass" ? "✓" : state === "fail" ? "✕" : "i"),
      el("div", { class: "status-text" },
        el("strong", { class: "status-title" }, title),
        sub ? el("span", { class: "status-sub" }, sub) : null));
  }

  function renderResults(res) {
    testEd.clearMarks();
    const findings = res.findings || [];
    const engineErrors = res.errors || [];
    const ann = res.annotations;
    const count = findings.length;
    const ranAt = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const runInfo = [res.duration != null ? `in ${res.duration} s` : "", res.engine ? `with ${res.engine}` : ""].filter(Boolean).join(" ");
    const sub = `${plural(count, "finding")}${runInfo ? ` ${runInfo}` : ""} · ran at ${ranAt}`;

    findings.forEach((f) => {
      testEd.markRange({ line: f.line, col: f.col }, { line: f.end_line, col: f.end_col }, "hl-finding");
      for (let l = f.line; l <= f.end_line; l++) testEd.markLine(l, "hl-finding-line");
    });

    let state;
    let title;
    let detail;
    const nodes = [];
    if (ann) {
      ann.results.forEach((r) => {
        const kind = resultKind(r);
        testEd.gutterMark(r.line, el("span", { class: `ann ann-${kind}`, title: r.reason || `${r.kind}: ok` }, ICON[kind] || "·"));
      });
      const failed = `${ann.failed} of ${ann.total} annotations failed`;
      state = ann.failed === 0 && !engineErrors.length ? "pass" : "fail";
      // With a broken rule the annotation counts are meaningless: errors first.
      title = engineErrors.length ? "The engine reported errors"
        : ann.failed ? failed : `Passed: ${ann.passed} of ${ann.total} annotations match`;
      detail = engineErrors.length ? `${failed} · ${sub}` : sub;

      const lines = testEd.get().split("\n");
      const failFirst = (r) => (r.status === "fail" ? 0 : 1);
      nodes.push(acceptAllBar(ann.results.filter((r) => r.kind === "unexpected").map((r) => r.line)),
        el("ul", { class: "res-list" }, ...ann.results.slice()
          .sort((x, y) => failFirst(x) - failFirst(y) || x.line - y.line)
          .map((r) => resultRow(r, withoutAnnotation(lines[r.line - 1]) || (lines[r.line - 1] || "").trim(), resultKind(r), r.reason))));
    } else {
      findings.forEach((f) => testEd.gutterMark(f.line, el("span", { class: "ann ann-hit", title: f.message }, ICON.hit)));
      state = engineErrors.length ? "fail" : "info";
      title = engineErrors.length ? "The engine reported errors" : count ? `Ran: ${plural(count, "finding")}` : "Ran: no findings";
      detail = [runInfo, `ran at ${ranAt}`, "No expectations yet: accept the findings below or click the margin next to a line."]
        .filter(Boolean).join(" · ");
      if (count) {
        const findingLines = [...new Set(findings.map((f) => f.line))];
        nodes.push(acceptAllBar(findingLines), el("ul", { class: "res-list" }, ...findingLines.map((l) => {
          const f = findings.find((x) => x.line === l);
          return resultRow({ kind: "finding", line: l }, (f.code || "").split("\n")[0].trim(), "hit", null);
        })));
      }
    }
    if (engineErrors.length) nodes.unshift(el("p", { class: "engine-error" }, engineErrors.join("\n")));
    showRunStatus(statusCard(state, title, detail));
    $("#results").replaceChildren(...nodes.filter(Boolean));
    return { state, title };
  }

  async function save() {
    if (S.readOnly) return toast("The editor is in read-only mode.", "error");
    let slug = S.slug;
    if (!slug) {
      slug = await askSlug();
      if (!slug) return;
    }
    try {
      const res = await api(`api/rules/${slug}`, { method: "PUT", body: { yaml: yamlEd.get(), test_code: testEd.get(), language: S.testLang } });
      S.slug = slug;
      setDirty(false);
      await loadRules();
      setDocName();
      const errs = (res.issues || []).filter((i) => i.level === "error").length;
      toast(errs ? `Rule saved, but with ${errs} validation ${errs === 1 ? "error" : "errors"}` : "Rule saved");
    } catch (e) { toast(e.message, "error"); }
  }

  // Registry-style ids (<lang>.<framework>.security.<name>) name the file
  // after their last segment.
  function ruleFileName(id) {
    const name = (id || "rule").split(".").filter(Boolean).pop() || "rule";
    return name.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "rule";
  }

  function askSlug() {
    const d = $("#dlg-save");
    const input = $("#form-save").elements.slug;
    const base = ruleFileName(S.fields?.id);
    let slug = base;
    for (let n = 2; S.rules.some((r) => r.slug === slug); n++) slug = `${base}-${n}`;
    input.value = slug;
    $("#save-path").textContent = "The rule and its test code are stored side by side in the rules folder, in the semgrep --test layout.";
    const closed = showDialog(d);
    input.select();
    return closed.then((ok) => (ok ? input.value.trim() : null));
  }

  async function removeRule() {
    if (!S.slug) return;
    const ok = await confirmDialog("Delete rule?", `${S.slug}.yaml and its test file will be deleted from the rules folder.`, "Delete");
    if (!ok) return;
    try {
      await api(`api/rules/${S.slug}`, { method: "DELETE" });
      toast("Rule deleted");
      S.slug = null;
      await loadRules();
      setDirty(true);
      setDocName();
    } catch (e) { toast(e.message, "error"); }
  }

  function download() {
    const blob = new Blob([yamlEd.get()], { type: "text/yaml" });
    const a = el("a", { href: URL.createObjectURL(blob), download: `${S.slug?.split("/").pop() || ruleFileName(S.fields?.id)}.yaml` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  async function newRule() {
    if (!(await guardDirty())) return;
    if (!(await showDialog($("#dlg-new")))) return;
    const f = $("#form-new").elements;
    try {
      const s = await api("api/templates/new", { method: "POST", body: { kind: f.kind.value, language: f.language.value, id: f.id.value } });
      loadDocument({ yaml: s.yaml, test_code: s.test_code, language: s.language });
    } catch (e) { toast(e.message, "error"); }
  }

  function openCve() {
    $("#cve-result").replaceChildren();
    $("#btn-cve-open").disabled = true;
    S.cve = null;
    $("#dlg-cve").showModal();
    $("#form-cve").elements.id.focus();
  }

  async function fetchCve(manual) {
    const f = $("#form-cve").elements;
    const box = $("#cve-result");
    box.replaceChildren(el("p", { class: "loading" }, manual ? "Generating drafts..." : `Looking up ${f.id.value.trim().toUpperCase()} in NVD and OSV...`));
    $("#btn-cve-open").disabled = true;
    try {
      const body = { language: f.language.value };
      let res;
      if (manual) {
        body.record = {
          id: f.id.value.trim() || "CVE-0000-0000", description: f.m_description.value, cwes: f.m_cwe.value,
          packages: f.m_package.value.trim() ? [{ ecosystem: f.m_ecosystem.value, name: f.m_package.value.trim(), fixed: f.m_fixed.value.trim() || null }] : [],
        };
        res = await api("api/cve/manual", { method: "POST", body });
      } else {
        body.id = f.id.value;
        res = await api("api/cve", { method: "POST", body });
      }
      S.cve = res;
      $("#cve-manual").open = false;
      renderCve(res);
    } catch (e) {
      box.replaceChildren(el("p", { class: "cve-error" }, e.message,
        manual ? null : " If the network is blocked, use the option to enter the data manually."));
      if (!manual) $("#cve-manual").open = true;
    }
  }

  function renderCve(res) {
    const r = res.record;
    const box = $("#cve-result");
    const pkgs = (r.packages || []).map((p) => `${p.name} (${p.ecosystem})${p.fixed ? `, fixed in ${p.fixed}` : ""}`);
    box.replaceChildren(
      el("div", { class: "cve-head" },
        el("div", { class: "cve-title" },
          el("span", { class: "cve-id" }, r.id),
          r.severity ? el("span", { class: `cve-sev sev-${r.severity}` }, `${r.severity}${r.cvss_score ? ` ${r.cvss_score}` : ""}`) : null,
          r.summary ? el("span", {}, r.summary) : null),
        r.description ? el("p", { class: "cve-desc" }, r.description.length > 420 ? `${r.description.slice(0, 420)}…` : r.description) : null,
        el("div", { class: "cve-facts" },
          r.cwes?.length ? el("span", {}, `CWE: ${r.cwes.join(", ")}`) : el("span", {}, "CWE not reported"),
          pkgs.length ? el("span", {}, `Packages: ${pkgs.join("; ")}`) : null,
          r.aliases?.length ? el("span", {}, `Also known as ${r.aliases.join(", ")}`) : null,
          r.sources?.length ? el("span", {}, `Source: ${r.sources.join(", ")}`) : null)),
      res.notes?.length ? el("ul", { class: "cve-notes" }, ...res.notes.map((n) => el("li", {}, n))) : null,
      el("div", { class: "cands", role: "radiogroup", "aria-label": "Drafts" }, ...res.candidates.map((c, i) =>
        el("label", { class: "cand" },
          el("input", { type: "radio", name: "cand", value: String(i), checked: i === 0 }),
          el("span", {},
            el("span", { class: "cand-title" }, `${c.title}, ${c.language}`),
            el("ul", { class: "cand-notes" }, ...(c.notes || []).map((n) => el("li", {}, n))))))));
    $("#btn-cve-open").disabled = !res.candidates.length;
  }

  async function openCandidate() {
    const i = Number(($("input[name=cand]:checked", $("#cve-result")) || {}).value || 0);
    const c = S.cve?.candidates?.[i];
    if (!c) return;
    if (!(await guardDirty())) return;
    $("#dlg-cve").close();
    $("#details").open = true;
    loadDocument({ yaml: c.yaml, test_code: c.test_code, language: c.language });
  }

  yamlEd.onChange(() => { setDirty(true); validateSoon(); runSoon(); });
  testEd.onChange(() => { setDirty(true); renderBadges(); runSoon(); });
  testEd.onCursor((line) => { if (revealedLine && line !== revealedLine) { revealedLine = null; renderBadges(); } });
  $("#raw-ann").addEventListener("change", renderBadges);
  form.addEventListener("input", () => mergeSoon());
  form.addEventListener("submit", (e) => e.preventDefault());
  $("#test-lang").addEventListener("change", (e) => { S.testLangManual = true; setTestLang(e.target.value); runSoon(); });
  $("#btn-run").addEventListener("click", () => runNow({ manual: true }));
  testEd.onGutterClick(cycleExpectation);
  $("#btn-save").addEventListener("click", save);
  $("#btn-delete").addEventListener("click", removeRule);
  $("#btn-download").addEventListener("click", download);
  $("#btn-new").addEventListener("click", newRule);
  $("#btn-cve").addEventListener("click", openCve);
  $("#form-cve").addEventListener("submit", (e) => { e.preventDefault(); fetchCve(false); });
  $("#btn-cve-manual").addEventListener("click", () => fetchCve(true));
  $("#btn-cve-close").addEventListener("click", () => $("#dlg-cve").close());
  $("#btn-cve-open").addEventListener("click", openCandidate);
  $("#filter").addEventListener("input", renderList);
  $("#details").addEventListener("toggle", () => { yamlEd.refresh(); });
  document.addEventListener("keydown", (e) => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); save(); }
    if (mod && e.key === "Enter") { e.preventDefault(); runNow({ manual: true }); }
  });
  window.addEventListener("beforeunload", (e) => { if (S.dirty) { e.preventDefault(); e.returnValue = ""; } });

  (async function boot() {
    try {
      S.info = await api("api/info");
      const eng = $("#engine");
      if (S.info.engine) eng.textContent = `${S.info.engine.name} ${S.info.engine.version}`;
      else { eng.textContent = "Engine not found"; eng.classList.add("missing"); }

      // regex exists only as a test language (container image drafts).
      const langs = S.info.languages.filter((l) => l.key !== "regex");
      fillSelect($("#test-lang"), S.info.languages, { value: "ruby" });
      fillSelect($("#new-lang"), langs.filter((l) => ["ruby", "python", "javascript", "typescript", "java", "go", "php", "csharp", "kotlin", "rust", "bash", "yaml", "dockerfile", "terraform", "generic"].includes(l.key)), { value: "ruby" });
      fillSelect($("#cve-lang"), langs.filter((l) => ["ruby", "python", "javascript", "java", "go"].includes(l.key)), { blank: "Detect" });
      fillSelect(form.elements.severity, S.info.severities.map((s) => ({ key: s, name: s })));

      const tpl = await api("api/templates");
      $("#kinds").replaceChildren(el("legend", { class: "sr-only" }, "Rule type"), ...tpl.starters.map((s, i) =>
        el("label", { class: "kind" }, el("input", { type: "radio", name: "kind", value: s.kind, checked: i === 0 }), s.title)));

      await loadRules();
      if (S.rules.length && !S.rules[0].error) {
        await openRule(S.rules[0].slug);
      } else {
        const s = await api("api/templates/new", { method: "POST", body: { kind: "patterns", language: "ruby", id: "my-rule" } });
        loadDocument({ yaml: s.yaml, test_code: s.test_code, language: s.language });
      }
    } catch (e) {
      toast(`Could not start: ${e.message}`, "error");
    }
  })();
})();
