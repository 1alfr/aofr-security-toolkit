# 🔐 cripto_aofr.py — Toolkit de Criptografia AES & RSA

> **AOFR TECH · v1.0**  
> Baseado no *Guia Definitivo AES & RSA — Edição 2025*

Ferramenta interactiva de criptografia aplicada com **14 módulos** que cobrem desde cifração simétrica e assimétrica até demonstrações educacionais de ataques clássicos a RSA.

---

## ✨ Funcionalidades

### Módulos Disponíveis

| # | Módulo | Descrição |
|---|---|---|
| 1 | **AES-CBC** | Cifração/decifração com padding PKCS7 |
| 2 | **AES-GCM** | Cifração autenticada AEAD — padrão recomendado |
| 3 | **AES-ECB** | Demo de insegurança do modo ECB *(educacional)* |
| 4 | **KDF** | Derivação de chave com PBKDF2 e scrypt |
| 5 | **RSA Keys** | Geração de par de chaves RSA e exportação PEM |
| 6 | **RSA-OAEP** | Cifração/decifração assimétrica |
| 7 | **RSA-PSS** | Assinatura digital e verificação |
| 8 | **Híbrido** | RSA-OAEP + AES-GCM (padrão TLS) |
| 9 | **Ficheiros** | Cifração de ficheiros com AES-GCM + scrypt |
| 10 | **JWT RS256** | Tokens com RSA + SHA-256 |
| 11 | **Wiener Attack** | Demo ataque Wiener (d pequeno) *(educacional)* |
| 12 | **Common Modulus** | Demo Common Modulus Attack *(educacional)* |
| 13 | **Certificado TLS** | Inspecionar certificado TLS de um servidor HTTPS |
| 14 | **ECB vs CBC** | Laboratório comparativo de padrões |

---

## 📦 Instalação

```bash
pip install pycryptodome PyJWT
```

---

## 🚀 Utilização

### Menu interactivo

```bash
python3 cripto_aofr.py
```

### CLI — Exemplos

```bash
# Executar todos os módulos
python3 cripto_aofr.py --todos

# Executar um módulo específico (ex: AES-GCM)
python3 cripto_aofr.py --modulo 2

# Cifrar um ficheiro com senha
python3 cripto_aofr.py --cifrar documento.pdf documento.pdf.enc --senha "MinhaSenha"

# Decifrar um ficheiro
python3 cripto_aofr.py --decifrar documento.pdf.enc documento.pdf --senha "MinhaSenha"

# Inspecionar certificado TLS
python3 cripto_aofr.py --tls google.com

# Gerar par de chaves RSA de 4096 bits e guardar em disco
python3 cripto_aofr.py --rsa-gerar 4096 --salvar --prefixo minha_chave
```

---

## 🧪 Exemplo de Output — AES-GCM

```
────────────────────────────────────────────────────────────
  MÓDULO 2 — AES-256-GCM: Cifração Autenticada (AEAD)
────────────────────────────────────────────────────────────
  [i] Plaintext  : Dados confidenciais AOFR TECH!
  [i] AAD        : AOFR-TECH-HEADER-v1 (autenticado, não cifrado)
  [i] Chave AES  : 3a7f...
  [i] Nonce      : 9c2e...
  [✓] Ciphertext : 8b4d1a...
  [✓] Tag GCM    : f92a... (128 bits de autenticação)
  [✓] Decifrado  : Dados confidenciais AOFR TECH!
  [✓] Adulteração detectada! Tag GCM inválida → dados rejeitados ✓
```

---

## 🏗️ Arquitectura

```
cripto_aofr.py
├── Utilitários (banner, cores ANSI, helpers)
├── Módulos AES (CBC, GCM, ECB, KDF, Ficheiros)
├── Módulos RSA (Keys, OAEP, PSS, Híbrido, JWT)
├── Módulos Educacionais (Wiener, Common Modulus)
├── Inspeção TLS (ssl stdlib)
└── CLI (argparse) + Menu interactivo
```

---

## 🔒 Recomendações de Segurança

- **AES-GCM** é o modo recomendado para novos projectos (AEAD).
- **AES-CBC** requer MAC separado — prefere GCM quando possível.
- **AES-ECB** nunca deve ser usado em produção — existe apenas para fins educacionais.
- Para derivação de chaves a partir de senhas, usa sempre **scrypt** ou **Argon2** (PBKDF2 apenas como fallback).
- Chaves RSA devem ter no mínimo **2048 bits**; recomendado **4096 bits** para dados sensíveis de longa duração.

---

## 📋 Dependências

| Pacote | Versão mínima | Uso |
|---|---|---|
| `pycryptodome` | ≥ 3.15 | AES, RSA, KDF, hashes |
| `PyJWT` | ≥ 2.0 | Tokens JWT RS256 |
| `ssl` (stdlib) | — | Inspeção TLS |

---

## 👤 Autor

**Alfredo Ociola Francisco Romano** · AOFR TECH · Luanda, Angola
