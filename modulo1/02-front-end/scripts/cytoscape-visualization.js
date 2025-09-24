/* global cytoscape */
(function () {
  const COLORS = {
    Spoofing: "#1f77b4",
    Tampering: "#ff7f0e",
    Repudiation: "#2ca02c",
    "Information Disclosure": "#d62728",
    "Denial of Service": "#9467bd",
    "Elevation of Privilege": "#8c564b",
  };

  // ------- Helpers -------
  function html(s = "") {
    return s.toString().replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  }
  window.html = html;

  function ensureKeys(t) {
    return {
      "Threat Type": t?.["Threat Type"] || "Unknown",
      Scenario: t?.Scenario || "",
      "Potential Impact": t?.["Potential Impact"] || "",
      Severity: t?.Severity || "",
      Mitigation: t?.Mitigation || "",
      CVEs: Array.isArray(t?.CVEs) ? t.CVEs : [],
    };
  }

  function normalizeThreats(threatModel) {
    if (!threatModel) return [];
    if (Array.isArray(threatModel)) return threatModel.filter(Boolean).map(ensureKeys);
    return [];
  }
  window.normalizeThreats = normalizeThreats;

  function badge(level) {
    const cls = level === "Alta" ? "high" : level === "Média" ? "med" : "low";
    return `<span class="badge ${cls}">${level}</span>`;
  }

  // ------- Tabela -------
  window.buildThreatRows = function(payload) {
    const threats = normalizeThreats(payload?.threat_model);
    if (!threats.length) return `<tr><td colspan="6" class="muted">Sem ameaças parseadas.</td></tr>`;
    return threats.map((t)=>{
      const sev = t.Severity || "Baixa";
      const cves = t.CVEs && t.CVEs.length ? t.CVEs : ["—"];
      return `
        <tr>
          <td>${html(t["Threat Type"])}</td>
          <td>${html(t.Scenario)}</td>
          <td>${html(t["Potential Impact"])}</td>
          <td>${badge(sev)}</td>
          <td>${html(t.Mitigation || "—")}</td>
          <td>${cves.map(c=>`<span class="badge">${html(c)}</span>`).join(" ")}</td>
        </tr>`;
    }).join("");
  };

  // ------- Styles -------
  function strideStyles(big = false) {
    return [
      { selector: "node",
        style: {
          "background-color": "#1e293b",
          "border-width": 2,
          "border-color": "#94a3b8",
          "label": "data(label)",
          "color": "#f1f5f9",
          "text-valign": "center",
          "text-halign": "center",
          "font-size": big ? 18 : 14,
          "font-weight": 600,
          "shape": "round-rectangle",
          "width": big ? 160 : 120,
          "height": big ? 70 : 50,
          "text-wrap": "wrap",
        }},
      { selector: "edge",
        style: {
          "width": 3,
          "line-color": "#64748b",
          "target-arrow-color": "#64748b",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "font-size": 11,
          "text-background-color": "#0f172a",
          "text-background-opacity": 0.7,
          "text-background-padding": 2,
          "label": "data(label)",
        }},
      ...Object.entries(COLORS).map(([k, v]) => ({
        selector: `edge[type = "${k}"]`,
        style: { "line-color": v, "target-arrow-color": v }
      })),
    ];
  }

  // ------- STRIDE inicial -------
  function makeStrideElements() {
    const cats = [
      "Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"
    ];
    const nodes = [{ data: { id: "stride-core", label: "STRIDE" } }];
    const edges = cats.map((c,i)=>({
      data:{id:`e-${i}`, source:"stride-core", target:c, type:c}
    }));
    return nodes.concat(cats.map(c=>({data:{id:c,label:c}}))).concat(edges);
  }

  // ------- Renderizações -------
  let _cyMain = null;
  let _cyInfra = null;

  // Grafo inicial STRIDE
  window.renderThreatGraph = function () {
    const container = document.getElementById("cy");
    if (!container) return;
    _cyMain = cytoscape({
      container,
      elements: makeStrideElements(),
      style: strideStyles(),
      layout: { name: "cose" },
      wheelSensitivity: 0.2,
    });
    _cyMain.fit();
  };

  // Grafo após análise
  window.renderReport = function (payload, meta) {
    // Resumo STRIDE (ameaças)
    const summaryContainer = document.getElementById("cy");
    if (summaryContainer && payload?.threat_model) {
      const threats = normalizeThreats(payload.threat_model);
      const elems = makeStrideElements();
      threats.forEach((t, idx) => {
        const nid = `t-${idx}`;
        elems.push({ data: { id: nid, label: t["Threat Type"] } });
        elems.push({ data: { id: `et-${idx}`, source: t["Threat Type"], target: nid, type: t["Threat Type"] }});
      });
      _cyMain = cytoscape({
        container: summaryContainer,
        elements: elems,
        style: strideStyles(),
        layout: { name: "cose" },
        wheelSensitivity: 0.2,
      });
      _cyMain.fit();
    }

    // Arquitetura sugerida
    const infraContainer = document.getElementById("cy-infra");
    if (infraContainer && payload?.best_practice_architecture) {
      const nodes = payload.best_practice_architecture.nodes.map((n)=>({
        data:{ id:n.id, label:n.label }
      }));
      const edges = payload.best_practice_architecture.edges.map((e,i)=>({
        data:{ id:`edge-${i}`, source:e.source, target:e.target, label:e.label || "" }
      }));
      _cyInfra = cytoscape({
        container: infraContainer,
        elements: nodes.concat(edges),
        style: strideStyles(true),
        layout: { name: "breadthfirst", directed:true, padding:20 },
        wheelSensitivity: 0.2,
      });
      _cyInfra.fit();
    }
  };
})();
