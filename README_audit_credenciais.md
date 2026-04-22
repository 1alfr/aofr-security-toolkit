# 🔑 audit_credenciais.py — Auditoria de Credenciais Padrão

> **AOFR TECH · v2.0**  
> Metodologia: PTES / OWASP / NIST

Ferramenta de auditoria de segurança que verifica se dispositivos de rede estão acessíveis com as credenciais de fábrica. Cobre **300+ dispositivos** em **10+ categorias** com suporte a verificação paralela via SSH e HTTP/HTTPS.

---

## ⚖️ Aviso Legal

> ⚠️ **USO EXCLUSIVO PARA AUDITORES AUTORIZADOS.**  
> Este script destina-se a auditores de segurança certificados com **autorização formal e escrita** dos proprietários dos sistemas alvo.  
> O uso não autorizado é crime (Angola Lei 7/17, CFAA EUA, NIS2 UE).

---

## ✨ Funcionalidades

- ✅ Base de dados com **300+ credenciais padrão** de fabricantes reais
- ✅ Suporte a protocolos **SSH, HTTP, HTTPS e Telnet**
- ✅ Verificação em paralelo com **threads configuráveis**
- ✅ Expansão de alvos por **IP individual, CIDR ou ficheiro**
- ✅ Filtragem por **categoria** (Router, Switch, Câmara IP, PLC, etc.)
- ✅ Relatórios em **JSON e CSV** com níveis de criticidade
- ✅ Pesquisa de credenciais por **fabricante**

### Categorias de Dispositivos

| Categoria | Exemplos |
|---|---|
| Router | Cisco, TP-Link, MikroTik, Huawei, ZTE, Ubiquiti |
| Switch | Cisco Catalyst, HP Aruba, Netgear, D-Link |
| Câmara IP | Hikvision, Dahua, Axis, Bosch |
| NAS | Synology, QNAP, WD |
| Firewall | Fortinet, pfSense, SonicWall |
| PLC / SCADA | Siemens, Schneider, Allen-Bradley |
| Impressora | HP, Ricoh, Canon, Xerox |
| UPS | APC, Eaton |
| VoIP | Cisco, Yealink, Grandstream |
| Servidor | iDRAC Dell, iLO HP, IPMI |

---

## 📦 Instalação

```bash
pip install requests paramiko
```

> `requests` — verificação HTTP/HTTPS  
> `paramiko` — verificação SSH

---

## 🚀 Utilização

### Menu interactivo

```bash
python3 audit_credenciais.py
```

### CLI — Exemplos

```bash
# Auditar uma subnet completa
python3 audit_credenciais.py -a 192.168.1.0/24

# Auditar IPs específicos
python3 audit_credenciais.py -a 192.168.1.1 192.168.1.254

# Auditar a partir de um ficheiro de alvos
python3 audit_credenciais.py -a alvos.txt --threads 50

# Filtrar por categoria
python3 audit_credenciais.py -a 10.0.0.0/24 -c Router Switch

# Pesquisar credenciais por fabricante
python3 audit_credenciais.py --fabricante Hikvision

# Listar todas as categorias disponíveis
python3 audit_credenciais.py --listar-categorias

# Verificar dependências instaladas
python3 audit_credenciais.py --deps

# Sem confirmação (para CI/automação com autorização prévia)
python3 audit_credenciais.py -a 10.0.0.0/24 --sem-confirmacao
```

### Formato do ficheiro de alvos (`alvos.txt`)

```
192.168.1.1
192.168.1.2
10.0.0.0/24
172.16.0.100
```

---

## 📊 Relatório Gerado

A ferramenta gera automaticamente relatórios na pasta `relatorios/` (ou directório configurado):

```
relatorios/
├── auditoria_2025-01-01_12-00.json   ← Detalhado (todos os resultados)
└── auditoria_2025-01-01_12-00.csv    ← Resumo para importar em Excel
```

### Estrutura do relatório JSON

```json
{
  "data_auditoria": "2025-01-01T12:00:00",
  "total_alvos": 254,
  "vulneraveis": 3,
  "resultados": [
    {
      "ip": "192.168.1.1",
      "fabricante": "MikroTik RouterOS",
      "usuario": "admin",
      "senha": "",
      "protocolo": "SSH",
      "porta": 22,
      "categoria": "Router",
      "gravidade": "CRÍTICA"
    }
  ]
}
```

---

## ⚙️ Parâmetros

| Parâmetro | Abreviatura | Padrão | Descrição |
|---|---|---|---|
| `--alvos` | `-a` | — | IPs, CIDRs ou ficheiro |
| `--categorias` | `-c` | todas | Filtrar por categoria |
| `--threads` | `-t` | 20 | Threads paralelas |
| `--timeout` | — | 5s | Timeout por ligação |
| `--output` | `-o` | `relatorios/` | Directório de saída |
| `--verbose` | `-v` | false | Mostrar todos os resultados |
| `--sem-confirmacao` | — | false | Saltar confirmação (CI) |

---

## 📋 Dependências

| Pacote | Obrigatório | Uso |
|---|---|---|
| `requests` | Recomendado | Verificação HTTP/HTTPS |
| `paramiko` | Recomendado | Verificação SSH |
| `socket` (stdlib) | ✅ Sempre | Verificação de porta aberta |

> **Nota:** Sem `requests` e `paramiko`, a ferramenta funciona apenas com verificação de porta TCP (sem autenticação).

---

## 👤 Autor

**Alfredo Ociola Francisco Romano** · AOFR TECH · Luanda, Angola
