import os, re, json, uuid, tempfile, base64
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, StreamingResponse

# ReportLab (PDF)
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer,
    ListFlowable, ListItem
)

# === PIL opcional (para reduzir custo do VLM) ===
try:
    from PIL import Image
    PIL_OK = True
except Exception:
    PIL_OK = False

# === .env / configs ===
ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
if ENV_PATH.exists():
    load_dotenv(ENV_PATH)

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "ollama")
LOCAL_VLM_MODEL = os.getenv("LOCAL_VLM_MODEL", "llava")
PUBLIC_HOST = os.getenv("PUBLIC_HOST", "http://localhost:8010")

REPORT_DIR = Path("/tmp/stride_relatorios")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# === OpenAI (Ollama compat) ===
from openai import OpenAI
client = OpenAI(base_url=OPENAI_BASE_URL, api_key=OPENAI_API_KEY, timeout=600)

# === FastAPI ===
app = FastAPI(title="STRIDE Threat Model (Local - Ollama)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # libera o front em 5500, etc.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- utils de parsing -----------------
def _extract_json_loose(text: str) -> Optional[dict]:
    """Extrai JSON de respostas com/sem cercas ```json ... ``` e corrige pequenos deslizes."""
    if not text:
        return None
    t = text.strip()
    fence = re.search(r"```json\s*([\s\S]*?)```", t, flags=re.IGNORECASE)
    candidate = fence.group(1).strip() if fence else (re.search(r"\{[\s\S]*\}", t).group(0) if re.search(r"\{[\s\S]*\}", t) else "")
    if not candidate:
        return None
    # remove vírgulas penduradas
    candidate = re.sub(r",\s*(\}|\])", r"\1", candidate)
    try:
        return json.loads(candidate)
    except Exception:
        candidate = candidate.replace("True", "true").replace("False", "false").replace("None", "null")
        try:
            return json.loads(candidate)
        except Exception:
            return None

def _ensure_threat_shape(t: Any) -> dict:
    if not isinstance(t, dict):
        return {"Threat Type": "Unknown", "Scenario": "", "Potential Impact": "", "Severity": "", "Mitigation": "", "CVEs": []}
    return {
        "Threat Type": t.get("Threat Type") or t.get("threat_type") or "Unknown",
        "Scenario": t.get("Scenario") or t.get("scenario") or "",
        "Potential Impact": t.get("Potential Impact") or t.get("impact") or "",
        "Severity": t.get("Severity") or t.get("severity") or "",
        "Mitigation": t.get("Mitigation") or t.get("mitigation") or "",
        "CVEs": t.get("CVEs") if isinstance(t.get("CVEs"), list) else [],
    }

def _normalize_threats(threat_model: Any) -> List[dict]:
    """Normaliza diferentes formatos de threat_model em uma lista uniforme de dicts."""
    if not threat_model:
        return []
    if isinstance(threat_model, list):
        return [_ensure_threat_shape(t) for t in threat_model]
    if isinstance(threat_model, dict):
        out = []
        for _, v in threat_model.items():
            items = v if isinstance(v, list) else [v]
            for it in items:
                out.append(_ensure_threat_shape(it))
        return out
    return []

def _unique_scenarios(threats: List[dict]) -> List[dict]:
    seen = set()
    uniq = []
    for t in threats:
        key = (t.get("Threat Type",""), t.get("Scenario","").strip().lower())
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq

# ----------------- inferência (correlação com contexto) -----------------
COMMON_TOP = [
    # (type, scenario, impact, sev, mitigation, cves)
    ("Spoofing", "Abuso de credenciais / phishing contra usuários e suporte", "Acesso não autorizado e movimentação lateral", "Alta", "MFA obrigatório, awareness, proteções anti-phishing, FIDO2", []),
    ("Tampering", "Injeção de SQL em endpoints críticos", "Exfiltração / corrupção de dados", "Alta", "ORM/prepared statements, validação e WAF (OWASP CRS)", []),
    ("Information Disclosure", "Dados sensíveis em logs (PII, tokens, segredos)", "Vazamento de PII/segredos", "Alta", "Mascaramento de logs, redaction, segregação de segredos em vault", []),
    ("Denial of Service", "HTTP Flood / abuso de recursos", "Indisponibilidade do serviço", "Alta", "Rate limiting, WAF, autoscaling controlado", ["CVE-2023-44487"]),
    ("Elevation of Privilege", "Permissões excessivas em serviços internos", "Comprometimento de contas privilegiadas", "Alta", "RBAC/ABAC, revisão periódica de privilégios", []),
    ("Repudiation", "Ausência de trilha de auditoria confiável", "Disputa de ações e fraudes internas", "Média", "Logs imutáveis, correlação SIEM, carimbo de tempo", []),
    ("Tampering", "XSS armazenado em módulos de administração", "Sequestro de sessão/admin", "Média", "CSP, escaping, sanitização de entrada", []),
    ("Information Disclosure", "S3/Blob Storage com ACLs permissivas", "Exposição pública de dados", "Alta", "Políticas least-privilege e scanners de exposição", []),
    ("Spoofing", "Reuso/roubo de JWT", "Acesso indevido prolongado", "Alta", "Rotacionar chaves, expiração curta, detecção de anomalias", ["CVE-2015-9235"]),
    ("Denial of Service", "Uploads sem limite/validação", "Exaustão de disco/CPU", "Média", "Limites de tamanho, validação de MIME, scans", []),
]

def _infer_threats_from_meta(tipo: str, auth: str, exposed: str, sens: str, descr: str) -> List[dict]:
    """Gera ameaças *correlatas* ao contexto informado pelo usuário."""
    t = (tipo or "").lower()
    a = (auth or "").lower()
    e = (exposed or "").lower()
    s = (sens or "").lower()
    d = (descr or "").lower()

    inferred: List[Tuple[str,str,str,str,str,List[str]]] = []

    # API / Microserviços
    if any(k in t for k in ["api", "rest", "graphql", "micro"]):
        inferred += [
            ("Tampering", "Injeção de comandos via API mal validada", "Execução não autorizada/alteração de estado", "Alta", "Validação robusta de payload, schema validation, WAF", []),
            ("Information Disclosure", "IDOR (Insecure Direct Object Reference) em recursos", "Exposição de dados de outros usuários", "Média", "Autorização por recurso (ABAC/RBAC) e testes de autorização", []),
        ]

    # Autenticação / IdP
    if any(k in a for k in ["jwt", "keycloak", "oidc", "saml", "aad", "azure ad", "ad "]):
        inferred += [
            ("Spoofing", "Assinatura JWT fraca/má validação de audience/issuer", "Assunção de identidade e acesso indevido", "Alta", "Validar iss/aud/alg, rotação de chaves, JTI + blacklist", []),
            ("Repudiation", "Falta de logs de autenticação e tentativas falhas", "Impossibilidade de rastrear abusos/ataques", "Média", "Centralizar logs de auth (IdP) no SIEM, alertas", []),
        ]

    # Exposição pública
    if any(k in e for k in ["pública", "publica", "internet", "exposta", "external"]):
        inferred += [
            ("Denial of Service", "Ataques volumétricos e aplicação (L7)", "Indisponibilidade e custos", "Alta", "CDN + WAF, rate-limit, desafiar bots, circuit breakers", []),
            ("Information Disclosure", "Headers de segurança ausentes", "Exploração por XSS/MiTM", "Média", "HSTS, CSP, X-Frame-Options, Referrer-Policy", []),
        ]

    # Dados sensíveis
    if any(k in s for k in ["pii", "cpf", "cartão", "cartao", "token", "segredo", "secret", "credencial"]):
        inferred += [
            ("Information Disclosure", "Segredos embutidos em repositório/variáveis não seguras", "Uso indevido/escala de ataque", "Alta", "Secrets manager, var. de ambiente, scanners de segredo", []),
            ("Tampering", "Criptografia em repouso ausente/fraca", "Integridade e confidencialidade comprometidas", "Alta", "KMS, chaves rotacionadas, AES-256, TDE/at-rest", []),
        ]

    # Palavras na descrição
    if "active directory" in d or "ad " in d or "kerberos" in d:
        inferred += [
            ("Spoofing", "Ataques Kerberos (Pass-the-Ticket/Golden Ticket)", "Domínio comprometido", "Alta", "Tiering AD, hardened KDC, monitorar TGT/TGS, gMSA", []),
            ("Elevation of Privilege", "Delegações e GPOs permissivas", "Escalada para admin de domínio", "Alta", "Revisão periódica de GPO, tiered admin, PAM", []),
        ]

    if "gateway" in d or "api gateway" in d or "reverse proxy" in d:
        inferred += [
            ("Tampering", "Bypass de regras do Gateway/Proxy", "Acesso indevido a backend", "Média", "Regra de allowlist, auth no Gateway + backend", []),
        ]

    # Banco de dados / storage
    if any(k in d for k in ["s3", "blob", "bucket", "minio", "database", "postgres", "mysql", "sqlserver", "mongodb"]):
        inferred += [
            ("Information Disclosure", "Buckets/DB expostos por configuração incorreta", "Exposição massiva de dados", "Alta", "VPC endpoints, políticas least-privilege, auditoria de ACL", []),
            ("Tampering", "Backups não protegidos/sem criptografia", "Restauração maliciosa/roubo de dados", "Média", "Criptografia, segregação de acesso e testes de restore", []),
        ]

    # Junta os comuns para garantir um baseline forte
    all_items = inferred + COMMON_TOP
    threats = [
        {
            "Threat Type": tt,
            "Scenario": sc,
            "Potential Impact": imp,
            "Severity": sev,
            "Mitigation": mit,
            "CVEs": cves,
        } for (tt, sc, imp, sev, mit, cves) in all_items
    ]
    return _unique_scenarios(threats)

def _ensure_min_10(threats: List[dict]) -> List[dict]:
    """Garante no mínimo 10 ameaças; se vier menos, completa com COMMON_TOP sem duplicar cenários."""
    base = _unique_scenarios(threats)
    if len(base) >= 10:
        return base[: max(10, len(base))]  # mantém todas (>=10)
    # completa
    for (tt, sc, imp, sev, mit, cves) in COMMON_TOP:
        cand = {"Threat Type": tt, "Scenario": sc, "Potential Impact": imp, "Severity": sev, "Mitigation": mit, "CVEs": cves}
        tmp = _unique_scenarios(base + [cand])
        if len(tmp) > len(base):
            base = tmp
        if len(base) >= 10:
            break
    return base

def _bp_text_from_graph(bp: dict) -> List[str]:
    """Converte best_practice_architecture (nodes/edges) em tópicos de texto."""
    if not isinstance(bp, dict):
        return []
    lines = []
    nodes = bp.get("nodes") or []
    edges = bp.get("edges") or []
    if nodes:
        lines.append("Componentes recomendados:")
        for n in nodes:
            label = n.get("label", "Componente")
            group = n.get("group", "zona")
            lines.append(f"- {label} (Zona: {group})")
    if edges:
        lines.append("Comunicações e controles sugeridos:")
        for e in edges:
            src = e.get("source", "origem")
            tgt = e.get("target", "destino")
            lb = e.get("label", "")
            if lb:
                lines.append(f"- {src} → {tgt} ({lb})")
            else:
                lines.append(f"- {src} → {tgt}")
    return lines

# ----------------- PDF builders -----------------
def _build_pdf_story(title: str, meta: Dict[str, Any], threats: List[dict], suggestions: List[str], bp_text: List[str]):
    """Monta a estrutura (story) do ReportLab com apenas texto/tabelas."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Heading1Blue", parent=styles["Heading1"], textColor=colors.HexColor("#0ea5e9")))
    styles.add(ParagraphStyle(name="Heading2Blue", parent=styles["Heading2"], textColor=colors.HexColor("#0ea5e9")))
    styles.add(ParagraphStyle(name="Muted", parent=styles["Normal"], textColor=colors.grey, fontSize=9))
    styles.add(ParagraphStyle(name="Cell", parent=styles["Normal"], leading=14))

    story = []
    story.append(Paragraph(title or "Relatório de Ameaças STRIDE", styles["Heading1Blue"]))
    story.append(Spacer(1, 6))

    # Metadados
    if meta:
        data = [[Paragraph("<b>Campo</b>", styles["Cell"]), Paragraph("<b>Valor</b>", styles["Cell"])]]
        for k, v in meta.items():
            data.append([Paragraph(str(k), styles["Cell"]), Paragraph(str(v) or "—", styles["Cell"])])
        t = Table(data, colWidths=[5.5*cm, None])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#122c3b")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#2c3948")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))

    # Ameaças
    story.append(Paragraph("Ameaças (STRIDE)", styles["Heading2Blue"]))
    if threats:
        head = ["Threat Type", "Scenario", "Potential Impact", "Severity", "Mitigation", "CVEs"]
        rows = [head]
        for trow in threats:
            rows.append([
                Paragraph(trow.get("Threat Type",""), styles["Cell"]),
                Paragraph(trow.get("Scenario",""), styles["Cell"]),
                Paragraph(trow.get("Potential Impact",""), styles["Cell"]),
                Paragraph(trow.get("Severity",""), styles["Cell"]),
                Paragraph(trow.get("Mitigation","") or "—", styles["Cell"]),
                Paragraph(", ".join(trow.get("CVEs") or []) or "—", styles["Cell"]),
            ])

        table = Table(
            rows,
            colWidths=[2.7*cm, 5.2*cm, 4.5*cm, 2.2*cm, 3.3*cm, None]
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#122c3b")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#2c3948")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("Sem ameaças parseadas.", styles["Muted"]))
    story.append(Spacer(1, 10))

    # Sugestões
    story.append(Paragraph("Improvement Suggestions", styles["Heading2Blue"]))
    if suggestions:
        items = [ListItem(Paragraph(str(s), styles["Normal"]), leftIndent=8) for s in suggestions]
        story.append(ListFlowable(items, bulletType="bullet", start="•", leftIndent=12))
    else:
        story.append(Paragraph("Sem sugestões registradas.", styles["Muted"]))
    story.append(Spacer(1, 10))

    # Boas práticas (texto)
    story.append(Paragraph("Arquitetura de Boas Práticas (visão textual)", styles["Heading2Blue"]))
    if bp_text:
        items = [ListItem(Paragraph(str(line), styles["Normal"]), leftIndent=8) for line in bp_text]
        story.append(ListFlowable(items, bulletType="bullet", start="•", leftIndent=12))
    else:
        story.append(Paragraph("Não foi fornecida uma visão textual de boas práticas.", styles["Muted"]))

    return story

def _build_pdf_stream(title: str, meta: Dict[str, Any], threats: List[dict], suggestions: List[str], bp_text: List[str]) -> BytesIO:
    """Gera o PDF em memória e devolve um BytesIO (para /export_pdf)."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm, topMargin=1.5*cm, bottomMargin=1.5*cm
    )
    story = _build_pdf_story(title, meta, threats, suggestions, bp_text)
    doc.build(story)
    buf.seek(0)
    return buf

def _build_pdf_file(filepath: Path, title: str, meta: Dict[str, Any], threats: List[dict], suggestions: List[str], bp_text: List[str]) -> Path:
    """Gera um PDF diretamente em arquivo (usado por /analisar_ameacas)."""
    doc = SimpleDocTemplate(
        str(filepath), pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm, topMargin=1.5*cm, bottomMargin=1.5*cm
    )
    story = _build_pdf_story(title, meta, threats, suggestions, bp_text)
    doc.build(story)
    return filepath

# ----------------- endpoint principal: analisa e já salva PDF (sem imagens) -----------------
@app.post("/analisar_ameacas")
async def analisar_ameacas(
    request: Request,
    imagem: UploadFile = File(...),
    tipo_aplicacao: str = Form(...),
    autenticacao: str = Form(...),
    acesso_internet: str = Form(...),
    dados_sensiveis: Optional[str] = Form(None),
    descricao_aplicacao: str = Form(...)
):
    """
    Observação: aceita também o campo 'dados_sensíveis' (com acento) vindo do Front.
    """
    try:
        # Corrige o campo com acento se vier do Front
        form_map = await request.form()
        if not dados_sensiveis:
            dados_sensiveis = form_map.get("dados_sensíveis") or None

        # Prompt que reforça a correlação com o contexto
        ds = dados_sensiveis or ""
        prompt = f"""
Aja como especialista de segurança (20+ anos) usando STRIDE.
Correlacione as ameaças diretamente ao contexto abaixo.
Liste PELO MENOS 10 ameaças comuns na prática, priorizando as mais exploradas neste tipo de arquitetura.
Responda ESTRITAMENTE em JSON:
- "threat_model": lista de objetos com "Threat Type" (uma das 6 STRIDE), "Scenario", "Potential Impact",
  "Severity" (Alta|Média|Baixa), "Mitigation" (ação objetiva), "CVEs" (array de strings).
- "improvement_suggestions": lista de bullets curtos e práticos.
- "best_practice_architecture": grafo com "nodes"/"edges" (WAF, API GW, AD/IdP, MFA, DMZ, segmentação, firewall, SIEM,
  secrets manager, backup/DR, observability etc).
- "architecture_class": "Simples" | "Média" | "Complexa" (apenas uma).
- "cost_options": array com 3 itens: "Baixo: ...", "Médio: ...", "Alto: ...".
Contexto:
Tipo de aplicação: {tipo_aplicacao}
Autenticação: {autenticacao}
Exposta na internet: {acesso_internet}
Dados sensíveis: {ds}
Descrição: {descricao_aplicacao}
""".strip()

        # salvar imagem temporária (opcional redimensionar)
        suffix = Path(imagem.filename).suffix or ".png"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            raw = await imagem.read()
            tmp.write(raw)
            temp_path = tmp.name

        # thumbnail opcional para reduzir custo de VLM
        use_path = temp_path
        if PIL_OK:
            try:
                im = Image.open(temp_path)
                im.thumbnail((1280, 1280))
                temp_jpg = temp_path + ".jpg"
                im.convert("RGB").save(temp_jpg, quality=85, optimize=True)
                use_path = temp_jpg
            except Exception:
                pass

        data_url = f"data:image/jpeg;base64,{base64.b64encode(open(use_path,'rb').read()).decode()}"

        # chamada ao modelo
        r = client.chat.completions.create(
            model=LOCAL_VLM_MODEL,
            messages=[{"role":"user","content":[
                {"type":"text","text": prompt},
                {"type":"image_url","image_url":{"url": data_url}}
            ]}],
            temperature=0, max_tokens=2200
        )
        raw_text = r.choices[0].message.content or ""
        parsed = _extract_json_loose(raw_text) or {}

        # normalizar e correlacionar com o contexto
        model_threats = _normalize_threats(parsed.get("threat_model"))
        inferred = _infer_threats_from_meta(tipo_aplicacao, autenticacao, acesso_internet, ds, descricao_aplicacao)

        # mescla e garante mínimo de 10
        threats = _ensure_min_10(_unique_scenarios(inferred + model_threats))

        # sugestões
        suggestions = parsed.get("improvement_suggestions") or [
            "Implementar MFA para acessos de usuários e administradores",
            "Ativar rate limiting e regras OWASP CRS no WAF/API Gateway",
            "Centralizar e correlacionar logs de autenticação no SIEM"
        ]

        # Grafo / texto de boas práticas
        best_arch = parsed.get("best_practice_architecture") or {
            "nodes": [
                {"id":"internet","label":"Internet","group":"Internet"},
                {"id":"waf","label":"WAF","group":"DMZ"},
                {"id":"gw","label":"API Gateway","group":"DMZ"},
                {"id":"idp","label":"AD/IdP","group":"Core"},
                {"id":"mfa","label":"MFA","group":"Core"},
                {"id":"apps","label":"Aplicações","group":"App"},
                {"id":"db","label":"Database","group":"Data"},
                {"id":"siem","label":"SIEM","group":"Core"},
                {"id":"vault","label":"Secrets Manager","group":"Core"},
                {"id":"fw","label":"Firewall/Segmentation","group":"Net"},
            ],
            "edges": [
                {"source":"internet","target":"waf","label":"TLS 1.2+"},
                {"source":"waf","target":"gw","label":"OWASP CRS"},
                {"source":"gw","target":"apps","label":"mTLS + JWT/OIDC"},
                {"source":"apps","target":"db","label":"TLS + Least Privilege"},
                {"source":"idp","target":"gw","label":"OIDC/SAML"},
                {"source":"apps","target":"siem","label":"Logs/Audit"},
                {"source":"vault","target":"apps","label":"Secrets"},
                {"source":"fw","target":"apps","label":"Segmentation"},
            ]
        }
        bp_text = parsed.get("bp_text") or _bp_text_from_graph(best_arch)

        # Classe e custos
        arch_class = parsed.get("architecture_class") or "Média"
        cost_options = parsed.get("cost_options") or [
            "Baixo: WAF básico + rate limiting; logs centralizados mínimos.",
            "Médio: MFA, SIEM básico, monitoramento e segmentação de rede.",
            "Alto: redundância, observabilidade completa, gestão avançada de segredos (HSM/KMS)."
        ]

        # gerar PDF e salvar em /tmp
        rid = uuid.uuid4().hex[:12]
        pdf_path = REPORT_DIR / f"{rid}.pdf"
        _build_pdf_file(
            filepath=pdf_path,
            title="Relatório de Ameaças STRIDE",
            meta={
                "Tipo de aplicação": tipo_aplicacao,
                "Autenticação": autenticacao,
                "Exposta na internet": acesso_internet,
                "Dados sensíveis": ds,
                "Descrição": descricao_aplicacao
            },
            threats=threats,
            suggestions=suggestions,
            bp_text=bp_text
        )

        return {
            "report_id": rid,
            "pdf_url": f"{PUBLIC_HOST}/relatorios/{rid}.pdf",
            "raw": raw_text,
            "parsed": {
                "threat_model": threats,
                "improvement_suggestions": suggestions,
                "best_practice_architecture": best_arch,
                "bp_text": bp_text,
                "architecture_class": arch_class,
                "cost_options": cost_options
            }
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ----------------- endpoint para download direto do PDF salvo -----------------
@app.get("/relatorios/{rid}.pdf")
def baixar_pdf(rid: str):
    pdf = REPORT_DIR / f"{rid}.pdf"
    if not pdf.exists():
        return JSONResponse(status_code=404, content={"error": "não encontrado"})
    return FileResponse(str(pdf), media_type="application/pdf", filename=f"relatorio_stride_{rid}.pdf")

# ----------------- endpoint para exportar PDF via JSON (botão 'Baixar PDF') -----------------
@app.post("/export_pdf")
async def export_pdf(payload: dict):
    """
    Espera JSON:
    {
      "title": "Relatório de Ameaças STRIDE",
      "meta": { ... },
      "threats": [ {Threat Type, Scenario, Potential Impact, Severity, Mitigation, CVEs[]} ],
      "suggestions": ["...", "..."],
      "bp_text": ["tópico 1", "tópico 2", ...]  # opcional; se ausente, tentamos 'best_practice_architecture'
      "best_practice_architecture": { "nodes": [...], "edges": [...] }  # opcional
    }
    """
    try:
        title = payload.get("title") or "Relatório de Ameaças STRIDE"
        meta = payload.get("meta") or {}
        threats = _ensure_min_10(_normalize_threats(payload.get("threats")))
        suggestions = payload.get("suggestions") or []

        bp_text = payload.get("bp_text")
        if not bp_text:
            bp_text = _bp_text_from_graph(payload.get("best_practice_architecture", {}))

        buf = _build_pdf_stream(title, meta, threats, suggestions, bp_text)
        return StreamingResponse(buf, media_type="application/pdf", headers={
            "Content-Disposition": "attachment; filename=relatorio_stride.pdf"
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"falha ao gerar PDF: {e}"})
