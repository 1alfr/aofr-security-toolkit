# 🏢 aofr_tech_audit.py — Auditoria Defensiva da Infra AOFR TECH

> **AOFR TECH · v2.0.0**  
> Stack: Laravel 11 · Nginx · MySQL · Redis · PHP 8.3 · Cloudflare

Ferramenta de auditoria de segurança defensiva desenvolvida especificamente para monitorização contínua de toda a infraestrutura da AOFR TECH. Cobre **12 departamentos** com verificações automáticas de portas, SSL/TLS, headers HTTP, DNS/Email e dorks Shodan + Google.

---

## ⚖️ Aviso Legal

> ⚠️ **USO EXCLUSIVO do proprietário da AOFR TECH** para auditoria dos seus próprios sistemas.  
> Aplicar estas técnicas em sistemas de terceiros sem autorização constitui crime nos termos da **Lei 17/22 de Angola** (Criminalidade Informática), Art. 4.º a 9.º.

---

## ✨ Funcionalidades

### Verificações Automáticas

| Módulo | O que verifica |
|---|---|
| 🔌 **Portas Expostas** | Verifica se portas críticas (MySQL 3306, Redis 6379, PHP-FPM 9000) estão abertas publicamente |
| 🔐 **SSL / TLS** | Versão TLS, expiração do certificado, cipher suites fracas |
| 📋 **Headers HTTP** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 📧 **DNS / Email** | SPF, DKIM, DMARC — prevenção de spoofing de email |
| 🌐 **Sub-Domínios** | Inventário e resolução DNS de todos os subdomínios activos |
| 🔍 **Dorks** | 1400+ queries Shodan e Google por departamento |

### Departamentos Cobertos

| Dep. | Área | Domínio |
|---|---|---|
| DEP.01 | Direcção Geral / Admin | admin.aofr.tech |
| DEP.02 | Site Corporativo | aofr.tech |
| DEP.03 | Blog / Content Hub | blog.aofr.tech |
| DEP.04 | Comercial / CRM | crm.aofr.tech |
| DEP.05 | Portal do Cliente | portal.aofr.tech |
| DEP.06 | Financeiro / ERP | erp.aofr.tech |
| DEP.07 | Técnico / Projectos | erp.aofr.tech/projectos |
| DEP.08 | Recursos Humanos | erp.aofr.tech/rh |
| DEP.09 | Suporte / Helpdesk | suporte.aofr.tech |
| DEP.10 | API Gateway | api.aofr.tech |
| DEP.11 | Email / Comunicação | mail.aofr.tech |
| DEP.12 | Monitorização / DevOps | monitor.aofr.tech |

---

## 📦 Instalação

Não requer dependências externas — usa apenas a biblioteca padrão do Python.

```bash
python3 aofr_tech_audit.py
```

---

## 🚀 Utilização

### Menu interactivo

```bash
python3 aofr_tech_audit.py
```

**Opções do menu:**

```
[1]  Auditoria Completa (todas as verificações automáticas + dorks)
[2]  Verificação de Portas Expostas
[3]  Verificação SSL / TLS
[4]  Verificação Headers HTTP
[5]  Verificação DNS — SPF · DKIM · DMARC
[6]  Inventário de Sub-Domínios
[7]  Listar todas as Dorks Shodan + Google
[8]  Tabela de Resposta a Incidentes
[9]  Glossário de Segurança
[0]  Sair
```

### CLI — Argumentos directos

```bash
# Auditoria completa automática
python3 aofr_tech_audit.py --completa

# Listar todas as dorks Shodan + Google
python3 aofr_tech_audit.py --dorks

# Tabela de resposta a incidentes
python3 aofr_tech_audit.py --resposta

# Glossário de segurança
python3 aofr_tech_audit.py --glossario
```

---

## 📊 Relatório Gerado

Após cada auditoria completa, um relatório JSON é gerado automaticamente em `/tmp/`:

```
/tmp/aofr_tech_auditoria_20250101_120000.json
```

### Estrutura do relatório

```json
{
  "empresa": "AOFR TECH",
  "auditor": "Alfredo Ociola Francisco Romano",
  "data_auditoria": "2025-01-01T12:00:00",
  "dominio_base": "aofr.tech",
  "total_problemas": 2,
  "criticos": 1,
  "altos": 1,
  "medios": 0,
  "problemas": [
    {
      "host": "erp.aofr.tech",
      "achado": "MySQL porta 3306 acessível publicamente",
      "gravidade": "CRÍTICA",
      "recomendacao": "Fechar no firewall — nunca deve ser pública"
    }
  ]
}
```

---

## 🚨 Portas Monitoradas

| Porta | Serviço | Estado Esperado |
|---|---|---|
| 80 | HTTP | ✅ Público |
| 443 | HTTPS | ✅ Público |
| 22 | SSH | ⚠️ Restrito a IPs |
| 25/587/465 | SMTP | ✅ Público (email) |
| 3306 | MySQL | ❌ NUNCA público |
| 6379 | Redis | ❌ NUNCA público |
| 9000 | PHP-FPM | ❌ NUNCA público |
| 3000 | Grafana | ⚠️ Restrito |
| 9090 | Prometheus | ⚠️ Restrito |

---

## 📅 Agenda de Auditoria Recomendada

```
Mensal:    Primeiro domingo de cada mês — auditoria completa
Semanal:   Verificação SSL e headers (5 minutos)
Contínuo:  Shodan Monitor activo para alertas automáticos
Pontual:   Após qualquer deploy em produção
```

---

## 🛡️ Próximos Passos Pós-Auditoria

1. Executar as dorks Shodan e Google (opção 7 do menu)
2. Corrigir os problemas detectados usando a Tabela de Resposta (opção 8)
3. Verificar [haveibeenpwned.com](https://haveibeenpwned.com) para todos os emails `@aofr.tech`
4. Activar Shodan Monitor para alertas automáticos
5. Agendar próxima auditoria completa

---

## 📋 Dependências

Apenas biblioteca padrão Python — **zero dependências externas**.

| Módulo | Uso |
|---|---|
| `ssl`, `socket` | Verificação SSL/TLS e portas |
| `urllib.request` | Verificação de headers HTTP |
| `subprocess` | Comandos DNS (dig/nslookup) |
| `json`, `datetime` | Relatórios e timestamps |

---

## 👤 Autor

**Alfredo Ociola Francisco Romano**  
Fundador — AOFR TECH  
📍 Luanda, Angola  
🌐 [aofr.tech](https://aofr.tech)

---

*AOFR TECH — Atitude · Orientação · Força · Resultados*
