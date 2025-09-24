# Agente STRIDE • IA para Análise de Arquitetura de TI  

Este projeto demonstra como **Inteligência Artificial** pode ser usada para **interpretar diagramas de arquitetura (imagens)** e aplicar a metodologia **STRIDE Threat Modeling**.  

O sistema recebe um **diagrama de arquitetura**, processa com um **modelo de visão + linguagem** (VLM, ex.: [Ollama LLaVA](https://ollama.com)), e retorna:  
- Lista de ameaças correlacionadas ao contexto da arquitetura.  
- Mitigações práticas.  
- CVEs relevantes (mínimo 10, para garantir amplitude).  
- Sugestão de arquitetura alternativa, explicada em texto e renderizada visualmente.  
- Classificação da arquitetura como **simples, média ou complexa**, com opções de **baixo, médio e alto custo de implementação**.  

---

## Objetivo

O foco do projeto é **testar a capacidade da IA em interpretar imagens de arquitetura** e **sugerir soluções de segurança**.  
- **Frontend responsivo** ainda não foi prioridade (pode ser ajustado no futuro).  
- **Relatórios PDF, gráficos interativos e extras** são bônus para enriquecer a entrega.

---

##  Tecnologias Usadas

- **Backend:** [FastAPI](https://fastapi.tiangolo.com/)  
- **Frontend (MVP):** HTML + CSS + JS + [Cytoscape.js](https://js.cytoscape.org/)  
- **IA Local:** [Ollama](https://ollama.com/) com modelo **LLaVA** (Vision + Language)  
- **PDF Reports:** ReportLab  
- **Outras libs:** Pillow, httpx, python-dotenv  

---

## Como Executar

### 1. Pré-requisitos
- Linux (ou WSL no Windows)  
- Python 3.12+  
- 16 GB RAM (mínimo recomendado)  
- GPU NVIDIA (opcional, fallback automático para CPU)  
- [Ollama](https://ollama.com/download) instalado  

### 2. Clone o repositório
```bash
git clone https://github.com/seu-usuario/Agente-Detecta-Vuln-Arq.git
cd Agente-Detecta-Vuln-Arq
```

### 3. Rode tudo com **um comando**
```bash
chmod -x dev.sh
bash dev.sh
```

O script `dev.sh` faz automaticamente:  
1. Criação do ambiente virtual.  
2. Instalação das dependências (`requirements.txt`).  
3. Checagem de GPU → fallback para CPU se necessário.  
4. Download do modelo Ollama (ex.: `llava`).  
5. Teste rápido de inferência (confirma se o modelo responde).  
6. Inicialização do backend em `http://localhost:8010`.  

---

## Como Usar

1. Abra o frontend em `modulo1/02-front-end/index.html`.  
2. Envie:  
   - Imagem (diagrama da arquitetura).  
   - Tipo de aplicação.  
   - Autenticação usada.  
   - Se é exposta na internet.  
   - Dados sensíveis tratados.  
   - Descrição do sistema.  
3. Clique em **Analisar**.  
4. A IA irá:  
   - Interpretar o diagrama.  
   - Correlacionar vulnerabilidades mais exploradas **no contexto da infra declarada**.  
   - Renderizar sugestões arquiteturais claras (nó maior, setas visíveis, texto explicativo).  
   - Classificar a arquitetura e propor opções de custo (baixo, médio, alto).  
5. Opcional: gerar relatório PDF consolidado.  

---

## Exemplo de Saída (simplificado)

**Entrada**:  
- Diagrama com API Gateway → Aplicação → Banco de Dados.  
- Autenticação via JWT.  
- Exposta publicamente.  

**Saída da IA**:  
- **Vulnerabilidades:**  
  - Reuso de JWT expostos (CVE-2015-9235, CVE-2022-29217)  
  - SQL Injection (CVE-2023-XYZ)  
  - Exposição indevida de dados sensíveis  
  - … (mínimo 10 listadas)  
- **Mitigações:**  
  - Rotação de tokens + MFA  
  - WAF com OWASP CRS  
  - TLS 1.2+  
  - Segregação de rede  
- **Arquitetura sugerida:**  
  - Versão simplificada (baixo custo): Firewall + TLS  
  - Versão intermediária (médio custo): WAF + Gateway + SIEM  
  - Versão robusta (alto custo): Segregação de zonas + Vault + PKI + SIEM integrado  
- **Classificação:** Arquitetura atual → simples; recomendação → intermediária.  


---

## Licença
Projeto sob licença MIT.  