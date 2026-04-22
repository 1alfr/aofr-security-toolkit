# 🔍 dorks_audit.py — Shodan & Google Dorks para Auditoria Defensiva

> **AOFR TECH · v1.0**  
> Metodologia: OWASP Top 10 · PTES · GHDB · NIST SP 800-115

Base de dados interactiva com **1400+ dorks** para Shodan e Google organizados em **20 categorias de login** e **10 categorias por fabricante**, com tabela de credenciais padrão e guia de defesa integrados.

---

## ⚖️ Aviso Legal

> ⚠️ **USO EXCLUSIVO EM AUDITORIAS DE SEGURANÇA AUTORIZADAS.**  
> Utilizar estes dorks para aceder a sistemas **sem autorização** constitui crime.  
> Metodologia defensiva — para identificar exposição nos *teus próprios sistemas*.

---

## ✨ Funcionalidades

- 📋 **1400+ dorks** Shodan e Google prontos a usar
- 🏷️ **20 categorias de login** (genéricos, admin, routers, câmaras, SCADA, VPN, etc.)
- 🏭 **10 categorias de fabricante** com 110+ modelos específicos
- 🔑 **300 credenciais padrão** tabeladas por fabricante
- ⚠️ Classificação de risco: **CRÍTICO / ALTO / MÉDIO / BAIXO**
- 🛡️ **Guia de defesa** para cada categoria
- 📖 **Glossário técnico** completo
- 📤 Exportação para **JSON** e **TXT**
- 🔎 Pesquisa rápida por fabricante ou tecnologia

### Categorias de Login (20)

| # | Categoria | Risco |
|---|---|---|
| 01 | Painéis de Login Genéricos | MÉDIO |
| 02 | Painéis de Administração Web | ALTO |
| 03 | Routers e Equipamentos de Rede | CRÍTICO |
| 04 | Câmaras IP e DVR/NVR | CRÍTICO |
| 05 | Sistemas SCADA / ICS / IoT Industrial | CRÍTICO |
| 06 | Bases de Dados Expostas | CRÍTICO |
| 07 | Servidores de Email | ALTO |
| 08 | VPN e Acesso Remoto | CRÍTICO |
| 09 | Sistemas de Monitorização | ALTO |
| 10 | Painéis de Hosting e DNS | ALTO |
| 11 | Git e Repositórios de Código | ALTO |
| 12 | Kubernetes e Containers | CRÍTICO |
| 13 | Serviços Cloud Expostos | ALTO |
| 14 | Dispositivos IoT Genéricos | MÉDIO |
| 15 | Impressoras em Rede | MÉDIO |
| 16 | Sistemas de Controlo de Acesso | CRÍTICO |
| 17 | NAS e Armazenamento em Rede | ALTO |
| 18 | Telefonia VoIP | ALTO |
| 19 | Painéis de Energia / UPS | MÉDIO |
| 20 | Ficheiros e Directórios Expostos | ALTO |

---

## 📦 Instalação

Não requer dependências externas — usa apenas a biblioteca padrão do Python.

```bash
python3 dorks_audit.py
```

---

## 🚀 Utilização

### Menu interactivo

```bash
python3 dorks_audit.py
```

### CLI — Argumentos directos

```bash
# Mostrar todos os dorks (login + fabricantes)
python3 dorks_audit.py --all

# Apenas dorks de login
python3 dorks_audit.py --login

# Apenas dorks de risco CRÍTICO
python3 dorks_audit.py --criticos

# Dorks por fabricante/modelo
python3 dorks_audit.py --fabricantes

# Tabela de credenciais padrão
python3 dorks_audit.py --credenciais

# Guia de defesa
python3 dorks_audit.py --defesa

# Glossário técnico
python3 dorks_audit.py --glossario

# Exportar para JSON
python3 dorks_audit.py --exportar-json

# Exportar para TXT
python3 dorks_audit.py --exportar-txt

# Pesquisa rápida
python3 dorks_audit.py --pesquisa=hikvision
python3 dorks_audit.py --pesquisa=cisco
python3 dorks_audit.py --pesquisa=mysql
```

---

## 🧪 Exemplo de Output

```
════════════════════════════════════════════════════════════════════════════════
  03 — Routers e Equipamentos de Rede
  Risco: CRÍTICO
════════════════════════════════════════════════════════════════════════════════

  SHODAN:
    http.title:"Router Login" port:80
    http.title:"MikroTik" port:80
    http.title:"FortiGate" port:443
    ...

  GOOGLE:
    intitle:"Router Login" inurl:login
    intitle:"MikroTik RouterOS" login
    ...

  CREDENCIAIS PADRÃO:
    MikroTik RouterOS  →  admin / (vazia)  [SSH 22]
    Cisco IOS Router   →  admin / admin    [SSH 22]
    ...
```

---

## 📤 Exportação

Os ficheiros exportados são gerados em `/tmp/` com timestamp:

```
/tmp/dorks_auditoria_20250101_120000.json
/tmp/dorks_auditoria_20250101_120000.txt
```

### Estrutura do JSON exportado

```json
{
  "data_exportacao": "2025-01-01T12:00:00",
  "total_dorks": 1400,
  "login_dorks": { ... },
  "fabricantes_dorks": { ... }
}
```

---

## 🛡️ Como usar defensivamente

1. Copia um dork Shodan e pesquisa em [shodan.io](https://shodan.io) com `org:"<tua_empresa>"` ou `net:<teu_IP>`
2. Copia um dork Google e pesquisa com `site:<teu_dominio>`
3. Se encontrares resultados para os teus sistemas → **corrige imediatamente**
4. Agenda verificação mensal

---

## 📋 Dependências

Apenas biblioteca padrão Python — **zero dependências externas**.

| Módulo | Uso |
|---|---|
| `sys`, `json`, `datetime` | Lógica e exportação |
| `urllib.parse` | Codificação de URLs para abrir no browser |
| `webbrowser` | Abrir dork directamente no browser |

---

## 👤 Autor

**Alfredo Ociola Francisco Romano** · AOFR TECH · Luanda, Angola
