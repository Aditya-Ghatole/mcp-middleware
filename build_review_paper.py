from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    FrameBreak,
    KeepTogether,
    NextPageTemplate,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Line, Rect, String


OUTPUT = Path("output/pdf/MCP_Middleware_Security_Review_Paper.pdf")


def p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text).replace("\n", "<br/>"), style)


def rich(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text, style)


def architecture_figure() -> Drawing:
    drawing = Drawing(245, 132)
    navy = colors.HexColor("#17365D")
    pale = colors.HexColor("#EAF1F8")
    amber = colors.HexColor("#FFF2CC")
    grey = colors.HexColor("#666666")

    boxes = [
        (5, 82, 68, 30, "MCP Host /\nAI Agent", pale),
        (89, 74, 75, 45, "Security\nMiddleware", amber),
        (178, 82, 62, 30, "MCP Tool\nServer", pale),
    ]
    for x, y, width, height, label, fill in boxes:
        drawing.add(Rect(x, y, width, height, fillColor=fill, strokeColor=navy, strokeWidth=0.8))
        lines = label.split("\n")
        for index, line in enumerate(lines):
            drawing.add(String(x + width / 2, y + height / 2 + 3 - index * 9, line,
                               textAnchor="middle", fontName="Helvetica-Bold", fontSize=7.2,
                               fillColor=navy))
    drawing.add(Line(73, 97, 88, 97, strokeColor=navy, strokeWidth=1.0))
    drawing.add(Line(164, 97, 177, 97, strokeColor=navy, strokeWidth=1.0))
    drawing.add(String(80, 102, "requests", textAnchor="middle", fontName="Helvetica", fontSize=5.8,
                       fillColor=grey))
    drawing.add(String(171, 102, "responses", textAnchor="middle", fontName="Helvetica", fontSize=5.8,
                       fillColor=grey))
    controls = [
        "protocol / identity checks", "least-privilege policy", "content provenance + tainting",
        "approval gates", "privacy-preserving audit"
    ]
    drawing.add(Rect(27, 8, 191, 48, fillColor=colors.white, strokeColor=grey, strokeWidth=0.6))
    drawing.add(String(122.5, 47, "Illustrative control plane", textAnchor="middle",
                       fontName="Helvetica-Bold", fontSize=6.5, fillColor=grey))
    for index, control in enumerate(controls):
        drawing.add(String(36, 38 - index * 6.2, "- " + control, fontName="Helvetica", fontSize=5.8,
                           fillColor=grey))
    return drawing


def footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 6.5)
    if doc.page > 1:
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(0.55 * inch, 10.72 * inch, "Security Middleware for MCP-Based AI Agents")
    canvas.setFillColor(colors.black)
    canvas.drawCentredString(4.25 * inch, 0.27 * inch, str(doc.page))
    canvas.restoreState()


def build() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "IEEEBody", parent=styles["BodyText"], fontName="Times-Roman", fontSize=8.35,
        leading=10.15, alignment=TA_JUSTIFY, spaceAfter=4.5, firstLineIndent=10,
    )
    body_no_indent = ParagraphStyle("BodyNoIndent", parent=body, firstLineIndent=0)
    abstract = ParagraphStyle(
        "Abstract", parent=body, fontSize=7.9, leading=9.35, leftIndent=1, rightIndent=1,
        firstLineIndent=0, spaceAfter=4,
    )
    keyword = ParagraphStyle(
        "Keywords", parent=body, fontSize=7.8, leading=9.1, firstLineIndent=0,
        alignment=TA_CENTER, spaceAfter=6,
    )
    section = ParagraphStyle(
        "Section", parent=styles["Heading1"], fontName="Times-Roman", fontSize=9.2,
        leading=11, alignment=TA_CENTER, spaceBefore=4.5, spaceAfter=4.0,
        keepWithNext=True,
    )
    subsection = ParagraphStyle(
        "Subsection", parent=styles["Heading2"], fontName="Times-Italic", fontSize=8.4,
        leading=10, alignment=TA_LEFT, spaceBefore=3.5, spaceAfter=2.5, keepWithNext=True,
    )
    title = ParagraphStyle(
        "Title", parent=styles["Title"], fontName="Times-Roman", fontSize=16.3,
        leading=18.1, alignment=TA_CENTER, spaceAfter=3,
    )
    author = ParagraphStyle(
        "Author", parent=body, fontName="Times-Roman", fontSize=8.2, leading=9.4,
        alignment=TA_CENTER, firstLineIndent=0, spaceAfter=0,
    )
    note = ParagraphStyle(
        "Note", parent=body, fontName="Times-Italic", fontSize=6.7, leading=7.8,
        alignment=TA_CENTER, firstLineIndent=0, textColor=colors.HexColor("#444444"),
    )
    caption = ParagraphStyle(
        "Caption", parent=body, fontSize=6.9, leading=8.0, firstLineIndent=0,
        alignment=TA_CENTER, spaceBefore=1.5, spaceAfter=4,
    )
    table_text = ParagraphStyle(
        "TableText", parent=body, fontSize=6.15, leading=7.15, firstLineIndent=0,
        spaceAfter=0,
    )
    table_head = ParagraphStyle(
        "TableHead", parent=table_text, fontName="Times-Bold", alignment=TA_CENTER,
    )
    ref = ParagraphStyle(
        "References", parent=body, fontSize=6.8, leading=8.0, leftIndent=13,
        firstLineIndent=-13, spaceAfter=1.7,
    )

    margin = 0.55 * inch
    gap = 0.18 * inch
    column_width = (letter[0] - 2 * margin - gap) / 2
    first_title = Frame(margin, 9.18 * inch, letter[0] - 2 * margin, 1.34 * inch,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="title")
    first_left = Frame(margin, 0.55 * inch, column_width, 8.52 * inch,
                       leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="first-left")
    first_right = Frame(margin + column_width + gap, 0.55 * inch, column_width, 8.52 * inch,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="first-right")
    later_left = Frame(margin, 0.55 * inch, column_width, 10.0 * inch,
                       leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="later-left")
    later_right = Frame(margin + column_width + gap, 0.55 * inch, column_width, 10.0 * inch,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="later-right")
    doc = BaseDocTemplate(
        str(OUTPUT), pagesize=letter, leftMargin=margin, rightMargin=margin,
        topMargin=0.45 * inch, bottomMargin=0.45 * inch,
        pageTemplates=[
            PageTemplate(id="First", frames=[first_title, first_left, first_right], onPage=footer),
            PageTemplate(id="Later", frames=[later_left, later_right], onPage=footer),
        ],
        title="Security Middleware for Model Context Protocol-Based AI Agents",
        author="Author Name(s) - draft for academic review",
    )

    story = []
    title_block = [
        rich("Security Middleware for Model Context Protocol-Based AI Agents:<br/>"
             "A Review of Threats, Defenses, and Design Challenges", title),
        p("Author Name(s) - Department / Institution - City, Country", author),
        p("email@example.edu", author),
        Spacer(1, 2),
        p("Draft review paper. Replace author details and verify institutional requirements before submission.", note),
    ]
    story.append(KeepTogether(title_block))
    story.append(NextPageTemplate("Later"))
    story.append(FrameBreak())

    story.append(rich("<b>Abstract</b>-Model Context Protocol (MCP) connects AI hosts to external tools, "
                      "resources, and services. This extensibility also creates a trust-boundary problem: "
                      "an agent may receive untrusted natural-language content and act on it using privileged "
                      "tools. This review examines the case for a security middleware layer positioned between "
                      "an MCP host and its tool servers. It synthesizes protocol guidance, agent-security research, "
                      "prompt-injection studies, and benchmark work to organize the MCP threat surface and the "
                      "available defensive controls. The review finds that a proxy can improve observability, policy "
                      "enforcement, provenance signaling, and approval handling, but cannot by itself create a "
                      "reliable separation between data and instructions inside a language model. The strongest "
                      "design is therefore defense in depth: capability-scoped access, explicit authorization, "
                      "input and output controls, taint-aware workflows, privacy-preserving audit, and measured "
                      "security-utility trade-offs. The paper identifies open issues that should guide the development "
                      "of an MCP middleware project, including bypass resistance, transitive taint propagation, "
                      "multimodal and multilingual attacks, classifier reliability, safe degradation, and reproducible evaluation.", abstract))
    story.append(rich("<b>Keywords</b>-Model Context Protocol, MCP security, AI agents, indirect prompt "
                      "injection, middleware, tool security, zero trust", keyword))

    story.append(p("I. INTRODUCTION", section))
    story.append(p("Model Context Protocol is an interoperability layer through which an AI host can discover "
                   "and invoke tools, retrieve resources, and exchange structured messages with servers [1]. "
                   "The protocol expands an agent's practical capability, but it also connects model reasoning to "
                   "data and actions owned by different principals. A file reader, database connector, email client, "
                   "or enterprise API may return content that is useful to the user while also carrying adversarial "
                   "instructions. If the agent treats those instructions as authoritative, the result can be data "
                   "exfiltration, unsafe tool use, or goal diversion.", body))
    story.append(p("This problem is broader than a malformed protocol message. Indirect prompt injection places "
                   "malicious language in content an application is expected to retrieve. Research has shown that "
                   "such content can manipulate LLM-integrated applications and influence downstream API use [6], [7]. "
                   "The 2025 OWASP guidance for LLM applications and the emerging OWASP MCP Top 10 both identify "
                   "prompt injection, excessive agency, insecure supply chains, and contextual payloads as material "
                   "risks [3], [4].", body))
    story.append(p("This review evaluates a project idea rather than a finished product: a trusted middleware "
                   "component that mediates the MCP host-server boundary. The objective is not to claim that a proxy "
                   "solves prompt injection. Rather, the objective is to identify which controls can be enforced at "
                   "that boundary, which protections must remain in the host, server, or identity system, and where "
                   "the approach can fail. The resulting requirements can guide an evolving implementation without "
                   "locking the project to one detector, transport, or framework.", body))

    story.append(p("II. REVIEW METHOD AND SCOPE", section))
    story.append(p("The review is a structured narrative synthesis. It draws on four source groups: the MCP "
                   "specification and authorization guidance [1], [2]; public security frameworks from NIST and "
                   "OWASP [3]-[5]; peer-reviewed or archival research on prompt injection and tool-using agents "
                   "[6]-[14]; and foundational zero-trust and OAuth standards [15]-[18]. Sources were selected for "
                   "their relevance to three questions: (RQ1) which MCP interactions introduce distinct trust "
                   "boundaries; (RQ2) which middleware controls reduce the associated risks; and (RQ3) what "
                   "limitations remain after deployment?", body))
    story.append(p("The scope is limited to defensive mediation around MCP-connected agents. It does not assess a "
                   "specific implementation, publish attack payloads, or claim benchmark results. Reported results "
                   "from prior work are used to motivate evaluation requirements, not to imply performance by the "
                   "proposed middleware. This distinction is essential while the project design and its individual "
                   "components remain under development.", body))

    story.append(p("III. MCP MEDIATION AND THE THREAT SURFACE", section))
    story.append(p("A. Trust Boundaries", subsection))
    story.append(p("An MCP deployment normally includes a host, an MCP client connection, one or more servers, "
                   "and external systems reached by server tools. The host may receive tool descriptions, resource "
                   "content, prompts, progress messages, and tool results. Each item may be structurally valid while "
                   "still being semantically untrustworthy. A middleware layer can observe and regulate this traffic, "
                   "but it must be treated as one control in a distributed trust model rather than as a universal "
                   "reference monitor.", body))
    story.append(architecture_figure())
    story.append(p("Fig. 1. Conceptual placement of an MCP security middleware layer. The figure shows design intent, "
                   "not a claim that all controls can be enforced by a proxy alone.", caption))
    story.append(p("B. Indirect Prompt Injection", subsection))
    story.append(p("Indirect prompt injection is particularly relevant when a tool returns natural-language data. "
                   "An attacker can place instructions in a document, web page, email, database field, or other "
                   "retrievable object. The agent may then confuse attacker-controlled text with user intent. BIPIA, "
                   "InjecAgent, and AgentDojo show why evaluation must consider both harmful action success and benign "
                   "task utility, rather than detector accuracy alone [8], [10], [11].", body))
    story.append(p("C. Authorization, Delegation, and Supply Chain", subsection))
    story.append(p("MCP authorization requirements apply particularly to HTTP transports, including audience "
                   "validation and OAuth security practices [2]. The protocol specification does not make a server "
                   "trustworthy merely because it is connected. A compromised or overly privileged server can offer "
                   "misleading tools, return hostile content, or misuse delegated credentials. Short-lived, "
                   "audience-bound tokens and proof-key protections reduce some identity risks [16]-[18], while "
                   "least privilege and explicit consent reduce the impact of a successful semantic attack.", body))
    story.append(p("D. Availability and Privacy", subsection))
    story.append(p("Inspection itself creates a new attack surface. Attackers can send oversized responses, use "
                   "costly encodings, trigger slow classifiers, or exploit logging. Conversely, a middleware that "
                   "stores raw prompts, tool arguments, or results may centralize sensitive data. Any proposed design "
                   "therefore needs message bounds, resource accounting, redaction rules, retention limits, and a "
                   "defined fail-open or fail-closed policy.", body))

    story.append(p("IV. DEFENSE TAXONOMY", section))
    table_rows = [
        [rich("<b>Control class</b>", table_head), rich("<b>Primary value and remaining limitation</b>", table_head)],
        [p("Protocol and identity", table_text), p("Bind clients, servers, and tokens to intended audiences; does not validate semantic trust in returned content.", table_text)],
        [p("Capability policy", table_text), p("Restrict tool names, arguments, destinations, and data scopes; requires complete and correct policy definitions.", table_text)],
        [p("Content normalization", table_text), p("Expose obfuscation such as hidden characters or encoded fragments; can alter legitimate data and remains incomplete.", table_text)],
        [p("Detection and tainting", table_text), p("Flag suspect content and preserve provenance; tags are advisory unless the host enforces their consequences.", table_text)],
        [p("Approval and confirmation", table_text), p("Adds human control before irreversible or high-impact actions; can cause alert fatigue or be bypassed by poor UX.", table_text)],
        [p("Audit and monitoring", table_text), p("Supports investigation and regression testing; can create privacy, retention, and access-control obligations.", table_text)],
    ]
    controls = Table(table_rows, colWidths=[0.98 * inch, 2.28 * inch], repeatRows=1)
    controls.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9EADBA")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(controls)
    story.append(p("TABLE I. DEFENSE CLASSES FOR MCP MIDDLEWARE", caption))
    story.append(p("A. Capability and Policy Enforcement", subsection))
    story.append(p("The most reliable controls constrain actions rather than interpret prose. A policy engine can "
                   "allow only registered tools, restrict argument schemas and data destinations, require explicit "
                   "approval for destructive actions, and deny requests that exceed a task's authority. This approach "
                   "aligns with zero-trust architecture, which avoids implicit trust based on network location or prior "
                   "access [15]. It is also complementary to task-alignment work that evaluates whether individual "
                   "actions serve the user's stated objective [13].", body))
    story.append(p("B. Content Inspection and Provenance", subsection))
    story.append(p("A middleware can normalize content before inspection, identify high-risk sources, classify "
                   "suspicious text, and attach provenance or taint labels. These steps reduce easy evasion and make "
                   "risk visible to the host. However, a wrapper around malicious text is not a hard isolation boundary: "
                   "the downstream model can still read the text and may still follow it. Instruction-hierarchy "
                   "training and boundary-aware prompting can help, but neither removes the need for tool-side and "
                   "host-side enforcement [8], [12].", body))
    story.append(p("C. Human Oversight and Safe Observability", subsection))
    story.append(p("Confirmation should be tied to impact. For example, an agent can retrieve a file without a "
                   "prompt, but sending its contents externally or changing a database should require a clear, "
                   "contextual approval. Audit records should capture event type, policy decision, timestamp, and "
                   "minimal metadata instead of indiscriminately storing private payloads. This allows incident "
                   "analysis without turning the security layer into an uncontrolled data repository.", body))

    story.append(p("V. DESIGN IMPLICATIONS FOR A PROPOSED MCP MIDDLEWARE", section))
    story.append(p("The review supports a modular architecture with a transparent data path and a separate control "
                   "plane. The data path should parse MCP messages, correlate request-response pairs, enforce size "
                   "and schema limits, and apply deterministic policy before forwarding. The control plane should "
                   "manage policies, approved tool inventories, access rules, and minimally retained audit events. "
                   "An analysis service may supply heuristic, statistical, or model-based signals, but its verdict "
                   "should not be the only protection.", body))
    story.append(p("The architecture should make trust explicit. Every artifact entering the agent context should "
                   "carry a source identity, risk class, and, where feasible, a provenance label. Tool calls should "
                   "be checked against a user-approved capability set, not just a global allow list. Responses that "
                   "contain untrusted instructions should trigger a policy decision: render as data, request approval, "
                   "redact a high-risk fragment, or deny a consequential downstream action. A project can begin with "
                   "deterministic rules and safely replace or supplement them with a classifier after measurement.", body))
    story.append(p("The choice of transport must remain an explicit project assumption. A local stdio proxy may be "
                   "useful for development, but it protects only traffic that is launched through it. Remote HTTP "
                   "servers introduce additional identity, authorization, network, and credential-handling concerns. "
                   "The paper therefore recommends transport-independent security requirements instead of claiming "
                   "that one deployment pattern secures all MCP uses.", body))

    story.append(p("VI. OPEN ISSUES AND RESEARCH GAPS", section))
    story.append(p("1) Proxy Bypass and Coverage: The strongest semantic filter is irrelevant if a host can connect "
                   "directly to the server or if only one transport is mediated. Deployment architecture, client "
                   "configuration, and enterprise policy must make mediation non-optional for protected workflows.", body_no_indent))
    story.append(p("2) Taint Does Not Equal Isolation: Labeling or wrapping untrusted content signals risk but does "
                   "not prevent an LLM from interpreting it. The unresolved challenge is transitive taint propagation: "
                   "how a label survives summarization, planning, memory, and later tool calls. This makes action "
                   "authorization more important than text filtering alone.", body_no_indent))
    story.append(p("3) Detection Errors and Adaptive Attackers: Rules, classifiers, and embeddings can be evaded by "
                   "paraphrase, multilingual phrasing, visual content, encoding, delayed instructions, and benign-looking "
                   "task decomposition. They can also block legitimate instructions, harming utility. Evaluation must "
                   "report false positives, false negatives, and impact on normal tasks [10], [11], [14].", body_no_indent))
    story.append(p("4) Incomplete Attack Coverage: Tool results are not the only channel. Tool metadata, resource "
                   "templates, server prompts, file names, image text, structured fields, and agent memory can all carry "
                   "influence. A text-only inbound scanner leaves important channels outside its security model.", body_no_indent))
    story.append(p("5) Privacy, Logging, and Compliance: Traceability can conflict with data minimization. The design "
                   "must specify exactly what metadata is stored, how it is redacted, who can retrieve it, how long it "
                   "is retained, and how users are informed. NIST's generative-AI profile reinforces the need to manage "
                   "risks across the system lifecycle [5].", body_no_indent))
    story.append(p("6) Benchmark Validity: A high block rate against static examples is not evidence of real agent "
                   "security. Benchmarks must include adaptive attacks, multi-turn tasks, legitimate tool use, and a "
                   "clearly defined adversary. Recent work cautions that weak metrics and benchmark flaws can make simple "
                   "defenses appear stronger than they are [14].", body_no_indent))
    story.append(p("7) Safe Failure Behavior: Blocking may preserve confidentiality but interrupt a critical task; "
                   "forwarding may preserve availability but expose users. A production design needs per-risk fail-safe "
                   "defaults, readable explanations, and a recovery path rather than one global mode.", body_no_indent))

    story.append(p("VII. RESEARCH AGENDA", section))
    story.append(p("A future implementation paper should evaluate the middleware in a controlled environment with "
                   "benign and adversarial MCP servers. The baseline should be direct host-server communication. "
                   "Comparisons should then add deterministic policy controls, provenance-aware handling, and any "
                   "classifier separately. Recommended metrics are attack success rate, harmful-tool-call prevention, "
                   "benign task completion, false-positive rate, median and tail latency, policy coverage, and audit "
                   "data exposure. AgentDojo, InjecAgent, and BIPIA provide useful starting points, but the study "
                   "should publish its own threat model, datasets, configurations, and failure cases [8], [10], [11].", body))
    story.append(p("The most valuable contribution may be a repeatable evaluation harness rather than a claim of "
                   "perfect defense. It should include poisoned and clean MCP resources, high-impact but sandboxed "
                   "tools, multiple languages and obfuscation methods, and tests for direct connection bypasses. "
                   "Human review of a sampled set of alerts can validate whether automated labels correspond to "
                   "operationally meaningful risks.", body))

    story.append(p("VIII. CONCLUSION", section))
    story.append(p("MCP gives AI agents a practical interface to tools and data, but the same interface transfers "
                   "untrusted content into an action-capable system. A security middleware layer is a promising place "
                   "to add protocol-aware policy, capability restrictions, provenance signals, approval gates, and "
                   "privacy-conscious observability. Its limits are equally important: it cannot guarantee that an LLM "
                   "will treat data as data, and it cannot secure paths it does not mediate. The core project idea is "
                   "therefore academically sound when framed as a defense-in-depth architecture and an evaluation problem, "
                   "not as a complete cure for prompt injection. Future work should prioritize measurable claims, "
                   "stronger threat models, and security controls that remain effective when text detection fails.", body))

    story.append(p("REFERENCES", section))
    references = [
        "[1] Model Context Protocol Steering Committee, \"Model Context Protocol Specification, version 2025-06-18,\" 2025. [Online]. Available: https://modelcontextprotocol.io/specification/2025-06-18/basic/index",
        "[2] Model Context Protocol Steering Committee, \"Authorization, version 2025-06-18,\" 2025. [Online]. Available: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
        "[3] OWASP Foundation, \"OWASP Top 10 for Model Context Protocol, v0.1,\" 2025. [Online]. Available: https://owasp.org/www-project-mcp-top-10/",
        "[4] OWASP Foundation, \"OWASP Top 10 for LLM and Generative AI Applications, v2.0,\" 2025. [Online]. Available: https://genai.owasp.org/llm-top-10/",
        "[5] NIST, \"Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile,\" NIST AI 600-1, Jul. 2024, doi: 10.6028/NIST.AI.600-1.",
        "[6] K. Greshake et al., \"Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection,\" arXiv:2302.12173, 2023.",
        "[7] Y. Liu et al., \"Prompt injection attack against LLM-integrated applications,\" arXiv:2306.05499, 2023.",
        "[8] J. Yi et al., \"Benchmarking and defending against indirect prompt injection attacks on large language models,\" arXiv:2312.14197, 2023.",
        "[9] Y. Ruan et al., \"Identifying the risks of LM agents with an LM-emulated sandbox,\" in Proc. ICLR, 2024.",
        "[10] E. Debenedetti et al., \"AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents,\" in Proc. NeurIPS Datasets and Benchmarks Track, 2024.",
        "[11] Q. Zhan, Z. Liang, Z. Ying, and D. Kang, \"InjecAgent: Benchmarking indirect prompt injections in tool-integrated large language model agents,\" arXiv:2403.02691, 2024.",
        "[12] E. Wallace et al., \"The instruction hierarchy: Training LLMs to prioritize privileged instructions,\" arXiv:2404.13208, 2024.",
        "[13] F. Jia, T. Wu, X. Qin, and A. Squicciarini, \"The Task Shield: Enforcing task alignment to defend against indirect prompt injection in LLM agents,\" arXiv:2412.16682, 2024.",
        "[14] R. Bhagwatkar et al., \"Indirect prompt injections: Are firewalls all you need, or stronger benchmarks?\" arXiv:2510.05244, 2025.",
        "[15] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, \"Zero Trust Architecture,\" NIST SP 800-207, Aug. 2020, doi: 10.6028/NIST.SP.800-207.",
        "[16] D. Hardt, \"The OAuth 2.0 Authorization Framework,\" IETF RFC 6749, Oct. 2012.",
        "[17] N. Sakimura, J. Bradley, and N. Agarwal, \"Proof Key for Code Exchange by OAuth Public Clients,\" IETF RFC 7636, Sep. 2015.",
        "[18] W. Denniss and J. Bradley, \"Resource Indicators for OAuth 2.0,\" IETF RFC 8707, Feb. 2020.",
    ]
    for reference in references:
        story.append(p(reference, ref))

    doc.build(story)


if __name__ == "__main__":
    build()
