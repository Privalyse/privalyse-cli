# 🚀 Privalyse: The "Visible Flows" Masterplan (1 Month)

This plan is designed to pivot Privalyse from "just another scanner" to a **Data Flow Visibility Engine**. The goal is to create a "WOW" effect by showing users *stories* about their data, not just error lists.

## 🗓️ Week 1: The Engine of Truth (Semantic Graph Core)
**Goal:** Ensure the backend actually produces the "Flow Stories" we promise. Move beyond simple regex/AST matching to a true graph representation.

- [x] **Refactor `Finding` Model**:
    - Add `source_node`, `sink_node`, and `flow_path` (list of nodes) to the `Finding` object.
    - Deprecate simple line-number-only findings where possible.
- [x] **Enhance `TaintTracker`**:
    - Ensure it captures the full path: `Source -> Transform -> Sink`.
    - Store "Context" for each step (e.g., "Inside `log_error` function").
- [x] **Graph Representation**:
    - Implement a lightweight internal graph structure (NetworkX or custom adjacency list) to represent the analyzed code.
    - Allow exporting this graph (JSON/DOT format) for debug/visualization.
- [x] **Proof of Concept**:
    - Create a test case `examples/flow-story-demo` that clearly demonstrates a multi-step leak.
    - Verify the scanner captures the full path.

## 🗓️ Week 2: The "Storyteller" UX (CLI & Visualization)
**Goal:** The CLI output must scream "Story", not "Log".

- [x] **CLI Output Redesign**:
    - Replace the standard list of errors with a "Flow View".
    - Use ASCII art or tree structures to show the path in the terminal.
    - Example:
      ```
      [HIGH] PII Leak Detected
      └── 📧 User Email (input.py:12)
          ⬇️
          📝 Formatted String (utils.py:45)
          ⬇️
          ☁️ External API (client.py:88)
      ```
- [x] **`--explain` Flag (LLM Integration)**:
    - Implement a feature that takes the *structured finding* (not just code) and asks an LLM to explain the *business risk*.
    - "This flow sends user emails to an unverified logging endpoint."
    - *Note: Implemented via structured JSON output with `code_context` and `suggested_fix` for external LLM consumption.*
- [x] **HTML/Markdown Report Upgrade**:
    - Embed Mermaid.js diagrams for each finding in the HTML/Markdown report.
    - Visualise the "Source -> Sink" path automatically.

## 🗓️ Week 3: Positioning & Content (The "Visual" Shift)
**Goal:** Align all external communication with the new "Visible Flows" vision.

- [x] **README Overhaul (Complete)**:
    - Integrate the "Visual Anchors" (Vision, Findings vs. Stories, Graph).
    - Use the new "Flow Story" terminology everywhere.
- [ ] **Documentation Update**:
    - Create a "How it Works" section explaining the Semantic Graph.
    - Add a "Gallery of Flows" showing common patterns (e.g., "The Silent Logger", "The Prompt Leaker").
- [ ] **Pitch Deck / Landing Page Assets**:
    - Generate high-quality screenshots of the new CLI output and HTML reports.
    - Create the "Before/After" comparison (Linter vs. Privalyse).

## 🗓️ Week 4: The "WOW" Launch
**Goal:** Release and make noise.

- [ ] **Pattern Mining Teaser**:
    - Release a blog post or doc section on "Common Data Flow Anti-Patterns" found by Privalyse.
- [ ] **Launch Video/Demo**:
    - A 30-second terminal recording (asciinema) showing a scan that reveals a complex data flow.
- [ ] **Community Outreach**:
    - Post on Reddit/Hacker News/Twitter with the angle: "Stop linting, start tracking flows."
    - Focus on the *visualization* aspect.

---

## 🧠 Key Differentiators to Keep in Mind

1.  **We don't just find bugs; we map territory.**
2.  **The LLM is the narrator, not the detective.** (The scanner provides the hard facts/graph; the LLM explains the story).
3.  **Context is King.** A variable named `password` is only a risk if it flows to a `log` or `http` sink.
