#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          AOFR TECH — Toolkit de Criptografia AES & RSA  v1.0        ║
║          Alfredo Ociola Francisco Romano                             ║
║          Baseado no Guia Definitivo AES & RSA — Edição 2025         ║
╚══════════════════════════════════════════════════════════════════════╝

Módulos:
  1  AES-CBC       — Cifração/decifração com padding PKCS7
  2  AES-GCM       — Cifração autenticada (AEAD) — padrão recomendado
  3  AES-ECB       — Demo de insegurança do modo ECB (educacional)
  4  KDF           — Derivação de chave com PBKDF2 e scrypt
  5  RSA Keys      — Geração de par de chaves RSA e exportação PEM
  6  RSA-OAEP      — Cifração/decifração assimétrica
  7  RSA-PSS       — Assinatura digital e verificação
  8  Híbrido       — RSA + AES-GCM (padrão TLS)
  9  Ficheiros     — Cifração de ficheiros com AES-GCM + scrypt
  10 JWT           — Tokens com RS256 (RSA + SHA-256)
  11 Wiener        — Demo ataque Wiener (d pequeno) [educacional]
  12 Common Mod    — Demo Common Modulus Attack [educacional]
  13 Certificado   — Inspecionar certificado TLS de um servidor
  14 ECB vs CBC    — Laboratório comparativo de padrões

Instalar dependências:
  pip install pycryptodome PyJWT
"""

import os
import sys
import base64
import struct
import json
import socket
import ssl
import datetime
import argparse
from math import isqrt

# ── Verificação de dependências ────────────────────────────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256, HMAC as CryptoHMAC
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Protocol.KDF import PBKDF2, scrypt
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

# ── Cores ANSI ─────────────────────────────────────────────────────────
AZUL    = "\033[94m"
VERDE   = "\033[92m"
AMARELO = "\033[93m"
VERMELHO= "\033[91m"
CIANO   = "\033[96m"
CINZA   = "\033[90m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

# ══════════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ══════════════════════════════════════════════════════════════════════

def banner():
    print(f"""{AZUL}{BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║   ██████╗ ██████╗ ███████╗██████╗     ████████╗███████╗ ██████╗██╗  ║
║  ██╔═══██╗██╔══██╗██╔════╝██╔══██╗       ██╔══╝██╔════╝██╔════╝██║  ║
║  ███████║██║  ██║█████╗  ██████╔╝       ██║   █████╗  ██║     ██║  ║
║  ██╔══██║██║  ██║██╔══╝  ██╔══██╗       ██║   ██╔══╝  ██║     ██╔╝  ║
║  ██║  ██║██████╔╝██║     ██║  ██║       ██║   ███████╗╚██████╗███║  ║
║  AES & RSA Toolkit v1.0  — Alfredo Ociola Francisco Romano          ║
╚══════════════════════════════════════════════════════════════════════╝{RESET}
""")

def titulo(texto: str):
    print(f"\n{CIANO}{BOLD}{'─'*60}")
    print(f"  {texto}")
    print(f"{'─'*60}{RESET}")

def ok(msg: str):
    print(f"  {VERDE}[✓]{RESET} {msg}")

def info(msg: str):
    print(f"  {AZUL}[i]{RESET} {msg}")

def aviso(msg: str):
    print(f"  {AMARELO}[!]{RESET} {msg}")

def erro(msg: str):
    print(f"  {VERMELHO}[✗]{RESET} {msg}")

def hex_preview(data: bytes, n: int = 32) -> str:
    h = data.hex()
    return h[:n*2] + ("…" if len(h) > n*2 else "")

def verificar_deps():
    if not HAS_CRYPTO:
        erro("pycryptodome não encontrado. Execute: pip install pycryptodome")
        sys.exit(1)

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 1 — AES-CBC
# ══════════════════════════════════════════════════════════════════════

def aes_cbc_cifrar(plaintext: bytes, key: bytes = None, iv: bytes = None):
    """
    Cifra bytes com AES-CBC (PKCS7 padding).
    Retorna (ciphertext, key, iv) — todos em bytes.
    """
    verificar_deps()
    key = key or get_random_bytes(32)   # AES-256 por padrão
    iv  = iv  or get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return ct, key, iv

def aes_cbc_decifrar(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decifra AES-CBC e remove padding."""
    verificar_deps()
    decipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(decipher.decrypt(ciphertext), AES.block_size)

def demo_aes_cbc(mensagem: str = "Mensagem secreta da AOFR TECH!"):
    titulo("MÓDULO 1 — AES-256-CBC: Cifração e Decifração")
    plaintext = mensagem.encode()
    info(f"Plaintext  : {mensagem}")

    ct, key, iv = aes_cbc_cifrar(plaintext)
    info(f"Chave AES  : {key.hex()}")
    info(f"IV         : {iv.hex()}")
    ok(f"Cifrado    : {hex_preview(ct)}")

    recovered = aes_cbc_decifrar(ct, key, iv)
    ok(f"Decifrado  : {recovered.decode()}")

    # Verifica integridade
    assert recovered == plaintext
    ok("Integridade verificada — plaintext == recovered ✓")

    return {"chave": key.hex(), "iv": iv.hex(),
            "ciphertext": base64.b64encode(ct).decode()}

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 2 — AES-GCM (AEAD — Recomendado)
# ══════════════════════════════════════════════════════════════════════

def aes_gcm_cifrar(plaintext: bytes, key: bytes = None,
                   nonce: bytes = None, aad: bytes = b""):
    """
    Cifra com AES-256-GCM.
    Retorna (ciphertext, tag, key, nonce).
    aad = Additional Authenticated Data (autenticado, não cifrado).
    """
    verificar_deps()
    key   = key   or get_random_bytes(32)
    nonce = nonce or get_random_bytes(12)   # 96 bits — padrão GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag, key, nonce

def aes_gcm_decifrar(ciphertext: bytes, tag: bytes, key: bytes,
                     nonce: bytes, aad: bytes = b"") -> bytes:
    """
    Decifra AES-GCM e VERIFICA autenticidade (tag).
    Lança ValueError se tag inválida (dados corrompidos/adulterados).
    """
    verificar_deps()
    decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        decipher.update(aad)
    return decipher.decrypt_and_verify(ciphertext, tag)

def demo_aes_gcm(mensagem: str = "Dados confidenciais AOFR TECH!"):
    titulo("MÓDULO 2 — AES-256-GCM: Cifração Autenticada (AEAD)")
    aad = b"AOFR-TECH-HEADER-v1"
    plaintext = mensagem.encode()

    info(f"Plaintext  : {mensagem}")
    info(f"AAD        : {aad.decode()} (autenticado, não cifrado)")

    ct, tag, key, nonce = aes_gcm_cifrar(plaintext, aad=aad)

    info(f"Chave AES  : {key.hex()}")
    info(f"Nonce      : {nonce.hex()}")
    ok(f"Ciphertext : {hex_preview(ct)}")
    ok(f"Tag GCM    : {tag.hex()} (128 bits de autenticação)")

    # Decifração normal
    data = aes_gcm_decifrar(ct, tag, key, nonce, aad=aad)
    ok(f"Decifrado  : {data.decode()}")

    # Demonstra detecção de adulteração
    ct_adulterado = bytearray(ct)
    ct_adulterado[0] ^= 0xFF  # Altera 1 bit
    try:
        aes_gcm_decifrar(bytes(ct_adulterado), tag, key, nonce, aad=aad)
        aviso("PROBLEMA: Adulteração não detectada!")
    except ValueError:
        ok("Adulteração detectada! Tag GCM invalida → dados rejeitados ✓")

    return {"chave": key.hex(), "nonce": nonce.hex(),
            "ciphertext": base64.b64encode(ct).decode(),
            "tag": tag.hex()}

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 3 — ECB vs CBC (Demo de Insegurança do ECB)
# ══════════════════════════════════════════════════════════════════════

def demo_ecb_vs_cbc():
    titulo("MÓDULO 3 — ECB vs CBC: Vazamento de Padrões")
    verificar_deps()

    key = get_random_bytes(16)  # AES-128 para o lab
    # Mensagem com 4 blocos idênticos de 16 bytes
    bloco = b"AOFR-TECH-BLOCK!"   # exatamente 16 bytes
    msg   = bloco * 4

    info(f"Mensagem: {'AOFR-TECH-BLOCK!'} × 4 (4 blocos idênticos de 16 bytes)")

    # ECB
    ecb = AES.new(key, AES.MODE_ECB)
    ct_ecb = ecb.encrypt(pad(msg, 16))

    # CBC
    iv = get_random_bytes(16)
    cbc_enc = AES.new(key, AES.MODE_CBC, iv)
    ct_cbc = cbc_enc.encrypt(pad(msg, 16))

    # Análise
    ecb_b0 = ct_ecb[0:16].hex()
    ecb_b1 = ct_ecb[16:32].hex()
    ecb_b2 = ct_ecb[32:48].hex()

    cbc_b0 = ct_cbc[0:16].hex()
    cbc_b1 = ct_cbc[16:32].hex()
    cbc_b2 = ct_cbc[32:48].hex()

    print(f"\n  {BOLD}ECB — blocos ciphertext:{RESET}")
    print(f"    Bloco 0: {ecb_b0}")
    print(f"    Bloco 1: {ecb_b1}  {'← IDÊNTICO! Vaza padrão' if ecb_b0==ecb_b1 else ''}")
    print(f"    Bloco 2: {ecb_b2}  {'← IDÊNTICO!' if ecb_b0==ecb_b2 else ''}")

    iguais_ecb = ecb_b0 == ecb_b1 == ecb_b2
    if iguais_ecb:
        erro("ECB: Blocos iguais → ciphertext idêntico → INSEGURO!")
    else:
        ok("ECB (sem blocos repetidos no teste)")

    print(f"\n  {BOLD}CBC — blocos ciphertext:{RESET}")
    print(f"    Bloco 0: {cbc_b0}")
    print(f"    Bloco 1: {cbc_b1}  {'← diferente ✓' if cbc_b0!=cbc_b1 else ''}")
    print(f"    Bloco 2: {cbc_b2}  {'← diferente ✓' if cbc_b0!=cbc_b2 else ''}")
    ok("CBC: Cada bloco é único graças ao encadeamento ✓")

    print(f"\n  {AMARELO}Conclusão: NUNCA use ECB para dados reais.{RESET}")
    print(f"  {VERDE}Use AES-GCM (AEAD) ou AES-CBC com HMAC (Encrypt-then-MAC).{RESET}")

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 4 — KDF: Derivação de Chave
# ══════════════════════════════════════════════════════════════════════

def derivar_chave_pbkdf2(password: str, salt: bytes = None,
                          iterations: int = 310_000) -> tuple[bytes, bytes]:
    """
    PBKDF2-HMAC-SHA256 — NIST recomenda ≥310.000 iterações (2023).
    Retorna (chave_32_bytes, salt).
    """
    verificar_deps()
    salt = salt or get_random_bytes(16)
    key = PBKDF2(password.encode(), salt, dkLen=32,
                 count=iterations,
                 prf=lambda p, s: CryptoHMAC.new(p, s, SHA256).digest())
    return key, salt

def derivar_chave_scrypt(password: str, salt: bytes = None,
                          N: int = 2**17, r: int = 8, p: int = 1) -> tuple[bytes, bytes]:
    """
    scrypt KDF — mais robusto que PBKDF2 contra ataques de hardware.
    N=2^17 (128 MB de memória) para produção.
    """
    verificar_deps()
    salt = salt or get_random_bytes(32)
    key = scrypt(password.encode(), salt, key_len=32, N=N, r=r, p=p)
    return key, salt

def demo_kdf(password: str = "MinhaSenh@Forte2025"):
    titulo("MÓDULO 4 — KDF: Derivação de Chave a partir de Senha")
    info(f"Senha      : {password}")

    import time

    # PBKDF2
    t0 = time.time()
    key_pbkdf2, salt1 = derivar_chave_pbkdf2(password)
    t1 = time.time()
    ok(f"PBKDF2-SHA256 (310k iter): {key_pbkdf2.hex()}")
    info(f"Tempo PBKDF2  : {(t1-t0)*1000:.0f} ms")

    # scrypt (N reduzido para demo rápida — em produção N=2^17)
    t2 = time.time()
    key_scrypt, salt2 = derivar_chave_scrypt(password, N=2**14)
    t3 = time.time()
    ok(f"scrypt (N=2^14 demo)      : {key_scrypt.hex()}")
    info(f"Tempo scrypt  : {(t3-t2)*1000:.0f} ms")

    # Reprodutibilidade
    key2, _ = derivar_chave_pbkdf2(password, salt=salt1)
    assert key2 == key_pbkdf2
    ok("KDF determinístico — mesma senha+salt → mesma chave ✓")

    aviso("Em produção: guarde o SALT junto ao ciphertext (não é segredo).")
    aviso("scrypt (N=2^17) usa ~128 MB RAM — resistente a GPUs.")

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 5 — RSA: Geração de Chaves
# ══════════════════════════════════════════════════════════════════════

def rsa_gerar_chaves(bits: int = 2048, passphrase: bytes = None,
                     salvar: bool = False,
                     prefixo: str = "aofr"):
    """
    Gera par de chaves RSA.
    Retorna (chave_privada_RSA, chave_publica_RSA).
    Opcionalmente salva em arquivos PEM.
    """
    verificar_deps()
    key = RSA.generate(bits)

    if salvar:
        prot = 'PBKDF2WithHMAC-SHA256AndAES256-CBC' if passphrase else None
        priv_pem = key.export_key(passphrase=passphrase, pkcs=8,
                                   protection=prot) if passphrase else key.export_key()
        pub_pem = key.publickey().export_key()
        with open(f"{prefixo}_privada.pem", "wb") as f:
            f.write(priv_pem)
        with open(f"{prefixo}_publica.pem", "wb") as f:
            f.write(pub_pem)

    return key, key.publickey()

def demo_rsa_gerar(bits: int = 2048):
    titulo(f"MÓDULO 5 — RSA-{bits}: Geração de Par de Chaves")
    info(f"Gerando RSA-{bits}…")

    import time
    t0 = time.time()
    priv, pub = rsa_gerar_chaves(bits)
    t1 = time.time()

    ok(f"Par de chaves gerado em {(t1-t0)*1000:.0f} ms")
    info(f"Módulo n           : {priv.n.bit_length()} bits")
    info(f"Expoente público e : {priv.e} (0x{priv.e:X})")
    info(f"Expoente privado d : {priv.d.bit_length()} bits (secreto)")
    info(f"Primo p            : {priv.p.bit_length()} bits")
    info(f"Primo q            : {priv.q.bit_length()} bits")

    pub_pem_preview = pub.export_key().decode().split("\n")[1][:40]
    info(f"Chave pública PEM  : {pub_pem_preview}…")

    return priv, pub

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 6 — RSA-OAEP: Cifração Assimétrica
# ══════════════════════════════════════════════════════════════════════

def rsa_oaep_cifrar(mensagem: bytes, pub_key) -> bytes:
    """Cifra com RSA-OAEP + SHA-256. IND-CCA2 seguro."""
    verificar_deps()
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    return cipher.encrypt(mensagem)

def rsa_oaep_decifrar(ciphertext: bytes, priv_key) -> bytes:
    """Decifra RSA-OAEP com chave privada."""
    verificar_deps()
    decipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    return decipher.decrypt(ciphertext)

def demo_rsa_oaep():
    titulo("MÓDULO 6 — RSA-OAEP + SHA-256: Cifração Assimétrica")
    priv, pub = rsa_gerar_chaves(2048)

    mensagem = b"Segredo AOFR TECH 2025 - Contrato Confidencial"
    info(f"Mensagem   : {mensagem.decode()}")
    info(f"Tamanho    : {len(mensagem)} bytes")

    ct = rsa_oaep_cifrar(mensagem, pub)
    ok(f"Cifrado    : {hex_preview(ct, 24)}… ({len(ct)} bytes)")

    # RSA-OAEP é probabilístico — mesma msg → ct diferente
    ct2 = rsa_oaep_cifrar(mensagem, pub)
    info(f"Mesmo msg, 2ª cifração: {hex_preview(ct2, 24)}… (DIFERENTE ✓ probabilístico)")
    assert ct != ct2
    ok("Padding OAEP garante aleatoriedade — IND-CCA2 ✓")

    # Decifração
    plain = rsa_oaep_decifrar(ct, priv)
    ok(f"Decifrado  : {plain.decode()}")
    assert plain == mensagem

    aviso(f"RSA-{priv.n.bit_length()} só cifra até ~{(priv.n.bit_length()//8) - 66} bytes.")
    aviso("Para mensagens longas: use criptografia HÍBRIDA (Módulo 8).")

    return priv, pub

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 7 — RSA-PSS: Assinatura Digital
# ══════════════════════════════════════════════════════════════════════

def rsa_pss_assinar(mensagem: bytes, priv_key) -> bytes:
    """Assina mensagem com RSA-PSS + SHA-256. EUF-CMA seguro."""
    verificar_deps()
    h = SHA256.new(mensagem)
    return pss.new(priv_key).sign(h)

def rsa_pss_verificar(mensagem: bytes, assinatura: bytes, pub_key) -> bool:
    """Verifica assinatura RSA-PSS. Retorna True se válida."""
    verificar_deps()
    h = SHA256.new(mensagem)
    try:
        pss.new(pub_key).verify(h, assinatura)
        return True
    except (ValueError, TypeError):
        return False

def demo_rsa_pss():
    titulo("MÓDULO 7 — RSA-PSS + SHA-256: Assinatura Digital")
    priv, pub = rsa_gerar_chaves(2048)

    documento = b"Contrato AOFR TECH - Valor: USD 500.000 - Data: 2025-01-01"
    info(f"Documento  : {documento.decode()}")

    sig = rsa_pss_assinar(documento, priv)
    ok(f"Assinatura : {hex_preview(sig, 24)}… ({len(sig)} bytes)")

    # Verificação válida
    valida = rsa_pss_verificar(documento, sig, pub)
    ok(f"Verificação original : {'VÁLIDA ✓' if valida else 'INVÁLIDA'}")

    # Documento adulterado
    doc_adulterado = documento + b" [ADULTERADO]"
    invalida = rsa_pss_verificar(doc_adulterado, sig, pub)
    ok(f"Documento adulterado: {'FALHOU — adulteração detectada ✓' if not invalida else 'PROBLEMA'}")

    # Assinatura adulterada
    sig_adulterada = bytearray(sig)
    sig_adulterada[10] ^= 0xAA
    invalida2 = rsa_pss_verificar(documento, bytes(sig_adulterada), pub)
    ok(f"Assinatura adulterada: {'FALHOU — integridade mantida ✓' if not invalida2 else 'PROBLEMA'}")

    return priv, pub, sig

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 8 — Criptografia Híbrida: RSA + AES-GCM
# ══════════════════════════════════════════════════════════════════════

def hibrido_cifrar(payload: bytes, pub_key) -> dict:
    """
    Cifração híbrida — padrão TLS/PGP:
    1. Gera chave de sessão AES-256 aleatória
    2. Cifra a chave de sessão com RSA-OAEP
    3. Cifra os dados com AES-256-GCM
    Retorna dict com todos os campos para transmissão.
    """
    verificar_deps()
    session_key = get_random_bytes(32)          # AES-256
    nonce       = get_random_bytes(12)          # GCM 96-bit nonce
    enc_sk      = rsa_oaep_cifrar(session_key, pub_key)
    aes         = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ct, tag     = aes.encrypt_and_digest(payload)
    return {
        "enc_session_key": base64.b64encode(enc_sk).decode(),
        "nonce":           nonce.hex(),
        "tag":             tag.hex(),
        "ciphertext":      base64.b64encode(ct).decode(),
    }

def hibrido_decifrar(pacote: dict, priv_key) -> bytes:
    """Decifra pacote híbrido com chave privada RSA."""
    verificar_deps()
    enc_sk  = base64.b64decode(pacote["enc_session_key"])
    nonce   = bytes.fromhex(pacote["nonce"])
    tag     = bytes.fromhex(pacote["tag"])
    ct      = base64.b64decode(pacote["ciphertext"])
    sk      = rsa_oaep_decifrar(enc_sk, priv_key)
    aes     = AES.new(sk, AES.MODE_GCM, nonce=nonce)
    return aes.decrypt_and_verify(ct, tag)

def demo_hibrido():
    titulo("MÓDULO 8 — Criptografia Híbrida: RSA-OAEP + AES-256-GCM")
    priv, pub = rsa_gerar_chaves(2048)

    # Payload grande (simula documento)
    payload = (
        "CONTRATO AOFR TECH — CONFIDENCIAL\n"
        "Partes: AOFR TECH Lda. e Cliente XYZ\n"
        "Valor: USD 500.000\n"
        "Vigência: 2025-01-01 a 2025-12-31\n"
        "Cláusulas: [texto legal extenso...]\n"
    ).encode() * 10   # ~1 KB de dados

    info(f"Payload    : {len(payload)} bytes")
    info("Fluxo      : session_key(AES) → cifrada c/ RSA-OAEP → transmite junto ao payload AES-GCM")

    pacote = hibrido_cifrar(payload, pub)
    ct_len = len(base64.b64decode(pacote["ciphertext"]))
    sk_len = len(base64.b64decode(pacote["enc_session_key"]))

    ok(f"Chave de sessão cifrada: {sk_len} bytes (RSA-OAEP)")
    ok(f"Payload cifrado        : {ct_len} bytes (AES-256-GCM)")
    ok(f"Tag GCM                : {pacote['tag']}")

    # Decifração
    resultado = hibrido_decifrar(pacote, priv)
    ok(f"Decifrado com sucesso! ({len(resultado)} bytes recuperados)")
    assert resultado == payload
    ok("payload == resultado ✓")

    info("Este é o esquema usado em TLS, PGP, SSH e S/MIME.")
    return pacote

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 9 — Cifração de Ficheiros (Produção-Ready)
# ══════════════════════════════════════════════════════════════════════

def cifrar_ficheiro(caminho_entrada: str, caminho_saida: str, senha: str,
                    N_scrypt: int = 2**17):
    """
    Cifra ficheiro com AES-256-GCM + scrypt KDF.
    Formato binário: [salt 32B][nonce 12B][tag 16B][ciphertext]
    """
    verificar_deps()
    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = scrypt(senha.encode(), salt, key_len=32, N=N_scrypt, r=8, p=1)

    with open(caminho_entrada, "rb") as f:
        plaintext = f.read()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)

    with open(caminho_saida, "wb") as f:
        f.write(salt + nonce + tag + ct)

    return len(plaintext), len(ct)

def decifrar_ficheiro(caminho_entrada: str, caminho_saida: str, senha: str,
                       N_scrypt: int = 2**17):
    """
    Decifra ficheiro cifrado por cifrar_ficheiro().
    Verifica autenticidade ANTES de escrever qualquer byte.
    """
    verificar_deps()
    with open(caminho_entrada, "rb") as f:
        dados = f.read()

    salt, nonce, tag = dados[:32], dados[32:44], dados[44:60]
    ct = dados[60:]
    key = scrypt(senha.encode(), salt, key_len=32, N=N_scrypt, r=8, p=1)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ct, tag)  # lança ValueError se falhar

    with open(caminho_saida, "wb") as f:
        f.write(plaintext)

    return len(plaintext)

def demo_ficheiro():
    titulo("MÓDULO 9 — Cifração de Ficheiro: AES-256-GCM + scrypt")
    import tempfile, os

    senha = "AOFR-Tech@2025-Ultra-Forte!"
    conteudo = b"Documento AOFR TECH - Dados altamente confidenciais\n" * 100

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tf:
        tf.write(conteudo); src = tf.name
    enc = src + ".enc"
    dec = src + ".dec"

    info(f"Ficheiro original : {len(conteudo)} bytes")
    info(f"Senha             : {senha}")
    info("KDF               : scrypt N=2^14 r=8 p=1 (demo — produção usa 2^17)")

    # Usa N menor para demo rápida
    n1, n2 = cifrar_ficheiro(src, enc, senha, N_scrypt=2**14)
    ok(f"Cifrado: {n2} bytes → {enc}")

    n3 = decifrar_ficheiro(enc, dec, senha, N_scrypt=2**14)
    ok(f"Decifrado: {n3} bytes → {dec}")

    with open(dec, "rb") as f:
        recovered = f.read()
    assert recovered == conteudo
    ok("Ficheiro recuperado integralmente ✓")

    # Testa senha errada
    try:
        decifrar_ficheiro(enc, dec + ".fail", "senha_errada", N_scrypt=2**14)
        aviso("PROBLEMA: senha errada não foi rejeitada!")
    except ValueError:
        ok("Senha incorreta detectada pela tag GCM ✓")

    for p in [src, enc, dec]:
        try: os.unlink(p)
        except: pass

    info("Formato: [salt 32B][nonce 12B][tag 16B][ciphertext ...]")

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 10 — JWT com RS256 (RSA-SHA256)
# ══════════════════════════════════════════════════════════════════════

def demo_jwt():
    titulo("MÓDULO 10 — JWT com RS256 (RSA + SHA-256)")
    if not HAS_JWT:
        aviso("PyJWT não encontrado. Execute: pip install PyJWT")
        return
    verificar_deps()

    priv, pub = rsa_gerar_chaves(2048)
    private_pem = priv.export_key().decode()
    public_pem  = pub.export_key().decode()

    payload = {
        "sub":  "alfredo.romano",
        "org":  "AOFR TECH",
        "role": "admin",
        "iat":  int(datetime.datetime.utcnow().timestamp()),
        "exp":  int((datetime.datetime.utcnow()
                     + datetime.timedelta(hours=1)).timestamp()),
    }

    token = pyjwt.encode(payload, private_pem, algorithm="RS256")
    info(f"Payload    : {json.dumps(payload, indent=None)}")
    ok(f"JWT        : {token[:60]}…")

    # Verifica
    decoded = pyjwt.decode(token, public_pem, algorithms=["RS256"])
    ok(f"Verificado : sub={decoded['sub']}, role={decoded['role']}")

    # Token adulterado
    partes = token.split(".")
    partes[1] = base64.urlsafe_b64encode(
        json.dumps({"sub": "hacker", "role": "superadmin"}).encode()
    ).decode().rstrip("=")
    token_falso = ".".join(partes)
    try:
        pyjwt.decode(token_falso, public_pem, algorithms=["RS256"])
        aviso("PROBLEMA: JWT adulterado aceito!")
    except Exception:
        ok("JWT adulterado rejeitado — assinatura RSA inválida ✓")

    aviso("NUNCA aceite algorithm='none' em JWT — verifique sempre explicitamente.")

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 11 — Ataque de Wiener (d pequeno) [Educacional]
# ══════════════════════════════════════════════════════════════════════

def _convergentes(n: int, d: int):
    """Gera convergentes da fração contínua de n/d."""
    h0, k0, h1, k1 = 1, 0, 0, 1
    while d:
        q = n // d
        h0, k0, h1, k1 = h1, k1, q*h1+h0, q*k1+k0
        yield h1, k1
        n, d = d, n % d

def wiener_attack(e: int, n: int):
    """
    Ataque de Wiener (1990): recupera d se d < n^0.25 / 3.
    Usa frações contínuas de e/n.
    Fonte: Wiener, M. (1990). Cryptanalysis of short RSA secret exponents.
    """
    for k, d in _convergentes(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Verifica se phi é válido: n - phi + 1 = p + q, disc >= 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            return d
    return None

def demo_wiener():
    titulo("MÓDULO 11 — Ataque de Wiener (d pequeno) [Educacional]")
    aviso("DEMO EDUCACIONAL — Ilustra por que 'd' pequeno é inseguro em RSA.")

    # RSA vulnerável pequeno para demonstração
    # p=1019, q=1021 → n=1040399; d=11 (muito pequeno)
    p, q = 1019, 1021
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # d pequeno intencional
    d = 11
    e = pow(d, -1, phi_n)

    info(f"n = p×q   : {n} (p={p}, q={q})")
    info(f"phi(n)    : {phi_n}")
    info(f"d (privado, FRACO): {d}")
    info(f"e (público): {e}")

    d_encontrado = wiener_attack(e, n)
    if d_encontrado == d:
        ok(f"d recuperado via Wiener: {d_encontrado} (correto! ✓)")
    elif d_encontrado:
        ok(f"d recuperado: {d_encontrado}")
    else:
        aviso("Wiener não recuperou d neste exemplo — ajuste os parâmetros.")

    # Cifra e decifra com o d encontrado
    M = 42
    C = pow(M, e, n)
    M_rec = pow(C, d_encontrado, n) if d_encontrado else None
    if M_rec == M:
        ok(f"Cifrou M={M} → C={C} → Decifrou M={M_rec} sem chave privada ✓")

    print(f"\n  {AMARELO}Prevenção:{RESET} Use implementações padrão (OpenSSL).")
    print(f"  {AMARELO}           Nunca minimize d manualmente. Use RSA-2048+ mínimo.{RESET}")

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 12 — Common Modulus Attack [Educacional]
# ══════════════════════════════════════════════════════════════════════

def _mdc_extendido(a: int, b: int) -> tuple[int, int, int]:
    """Algoritmo de Euclides Extendido: retorna (g, x, y) tal que a*x + b*y = g."""
    if b == 0:
        return a, 1, 0
    g, x, y = _mdc_extendido(b, a % b)
    return g, y, x - (a // b) * y

def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int):
    """
    Common Modulus Attack:
    Se mdc(e1, e2)=1 e mesma mensagem M cifrada com mesmo n:
      C1 = M^e1 mod n, C2 = M^e2 mod n
      Via Bezout: M = C1^a × C2^b mod n
    """
    g, a, b = _mdc_extendido(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n

def demo_common_modulus():
    titulo("MÓDULO 12 — Common Modulus Attack [Educacional]")
    aviso("DEMO EDUCACIONAL — Ilustra por que reutilizar 'n' é perigoso.")

    p, q = 1031, 1033
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Dois pares de expoentes com mesmo n
    e1, e2 = 17, 11
    d1 = pow(e1, -1, phi_n)
    d2 = pow(e2, -1, phi_n)

    M = 123   # mensagem original
    C1 = pow(M, e1, n)
    C2 = pow(M, e2, n)

    info(f"n = {n} (mesmo para ambos os destinatários)")
    info(f"Mesma mensagem M = {M} cifrada para 2 destinatários")
    info(f"C1 = M^e1 mod n = {C1}  (e1={e1})")
    info(f"C2 = M^e2 mod n = {C2}  (e2={e2})")

    M_rec = common_modulus_attack(n, e1, e2, C1, C2)
    if M_rec == M:
        ok(f"M recuperado sem chave privada: {M_rec} ✓")
    else:
        aviso(f"Resultado: {M_rec} (esperado {M})")

    print(f"\n  {AMARELO}Prevenção:{RESET} NUNCA use o mesmo módulo n para destinatários diferentes.")
    print(f"  {AMARELO}           Use padding OAEP — torna o ataque inviável mesmo com n partilhado.{RESET}")

# ══════════════════════════════════════════════════════════════════════
# MÓDULO 13 — Inspecionar Certificado TLS de um Servidor
# ══════════════════════════════════════════════════════════════════════

def inspecionar_tls(host: str, porta: int = 443, timeout: int = 5):
    """
    Liga-se a um servidor HTTPS e extrai informações do certificado TLS.
    Não requer pycryptodome — usa ssl stdlib.
    """
    titulo(f"MÓDULO 13 — Inspecionar Certificado TLS: {host}:{porta}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, porta))
            cert   = s.getpeercert()
            cipher = s.cipher()
            ver    = s.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        ok(f"Ligação TLS estabelecida")
        info(f"Versão TLS    : {ver}")
        info(f"Cipher suite  : {cipher[0] if cipher else 'N/A'}")
        info(f"Subject CN    : {subject.get('commonName', 'N/A')}")
        info(f"Organização   : {subject.get('organizationName', 'N/A')}")
        info(f"Emissor (CA)  : {issuer.get('commonName', 'N/A')}")
        info(f"Válido até    : {cert.get('notAfter', 'N/A')}")
        info(f"SANs (DNS)    : {', '.join(sans[:5])}{'…' if len(sans)>5 else ''}")

        # Avaliação da cipher suite
        if cipher:
            c = cipher[0]
            if "GCM" in c:
                ok(f"Cipher usa AEAD (GCM) — excelente ✓")
            elif "CBC" in c:
                aviso(f"Cipher usa CBC — verificar se há MAC adequado")
            if "TLS_AES" in c or "CHACHA20" in c:
                ok(f"TLS 1.3 cipher suite ✓")

        return cert

    except ssl.SSLCertVerificationError as e:
        erro(f"Certificado inválido: {e}")
    except socket.timeout:
        erro(f"Timeout ao ligar a {host}:{porta}")
    except Exception as e:
        erro(f"Erro: {e}")
    return None

# ══════════════════════════════════════════════════════════════════════
# RUNNER — MENU INTERATIVO
# ══════════════════════════════════════════════════════════════════════

MODULOS = {
    "1":  ("AES-CBC        — Cifração/Decifração",          demo_aes_cbc),
    "2":  ("AES-GCM        — Cifração Autenticada (AEAD)",  demo_aes_gcm),
    "3":  ("ECB vs CBC     — Demo de insegurança ECB",      demo_ecb_vs_cbc),
    "4":  ("KDF            — PBKDF2 e scrypt",              demo_kdf),
    "5":  ("RSA Keys       — Geração de par de chaves",     lambda: demo_rsa_gerar(2048)),
    "6":  ("RSA-OAEP       — Cifração assimétrica",         demo_rsa_oaep),
    "7":  ("RSA-PSS        — Assinatura digital",           demo_rsa_pss),
    "8":  ("Híbrido        — RSA-OAEP + AES-256-GCM",       demo_hibrido),
    "9":  ("Ficheiros      — Cifração AES-GCM + scrypt",    demo_ficheiro),
    "10": ("JWT RS256      — Tokens com RSA",               demo_jwt),
    "11": ("Wiener Attack  — d pequeno [educacional]",      demo_wiener),
    "12": ("Common Modulus — Mesmo n [educacional]",        demo_common_modulus),
    "13": ("Certificado TLS— Inspecionar servidor HTTPS",   None),  # requer arg
}

def menu():
    banner()
    print(f"  {BOLD}Módulos disponíveis:{RESET}")
    for k, (desc, _) in MODULOS.items():
        cat = "educacional" if "educacional" in desc else ""
        cor = AMARELO if cat else CIANO
        print(f"  {cor}[{k:>2}]{RESET} {desc}")
    print(f"  {CINZA}[  0  ] Executar TODOS os módulos{RESET}")
    print(f"  {CINZA}[  q  ] Sair{RESET}\n")

    escolha = input(f"  {BOLD}Selecione um módulo:{RESET} ").strip()

    if escolha == "q":
        print(f"\n  {CINZA}AOFR TECH — Encerrando.{RESET}\n")
        sys.exit(0)

    if escolha == "0":
        for k, (_, fn) in MODULOS.items():
            if fn and k != "13":
                try:
                    fn()
                except Exception as e:
                    erro(f"Módulo {k} falhou: {e}")
        return

    if escolha == "13":
        host = input("  Host HTTPS (ex: google.com): ").strip() or "google.com"
        inspecionar_tls(host)
        return

    if escolha in MODULOS:
        _, fn = MODULOS[escolha]
        if fn:
            fn()
        else:
            host = input("  Host HTTPS: ").strip() or "google.com"
            inspecionar_tls(host)
    else:
        aviso(f"Opção '{escolha}' inválida.")

# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def cli():
    parser = argparse.ArgumentParser(
        description="AOFR TECH — Toolkit AES & RSA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python cripto_aofr.py --todos
  python cripto_aofr.py --modulo 2
  python cripto_aofr.py --cifrar doc.pdf doc.pdf.enc --senha "MinhaSenha"
  python cripto_aofr.py --decifrar doc.pdf.enc doc.pdf --senha "MinhaSenha"
  python cripto_aofr.py --tls google.com
  python cripto_aofr.py --rsa-gerar 4096 --salvar --prefixo minha_chave
"""
    )
    parser.add_argument("--modulo",   type=str, help="Executar módulo específico (1-13)")
    parser.add_argument("--todos",    action="store_true", help="Executar todos os módulos")
    parser.add_argument("--cifrar",   nargs=2, metavar=("ENTRADA", "SAIDA"))
    parser.add_argument("--decifrar", nargs=2, metavar=("ENTRADA", "SAIDA"))
    parser.add_argument("--senha",    type=str, help="Senha para cifração de ficheiro")
    parser.add_argument("--tls",      type=str, metavar="HOST", help="Inspecionar TLS")
    parser.add_argument("--porta",    type=int, default=443)
    parser.add_argument("--rsa-gerar",type=int, metavar="BITS", help="Gerar par RSA (2048/4096)")
    parser.add_argument("--salvar",   action="store_true", help="Salvar chaves PEM em disco")
    parser.add_argument("--prefixo",  type=str, default="aofr", help="Prefixo dos ficheiros PEM")

    args = parser.parse_args()

    banner()

    if args.rsa_gerar:
        titulo(f"Gerando RSA-{args.rsa_gerar}…")
        verificar_deps()
        priv, pub = rsa_gerar_chaves(args.rsa_gerar, salvar=args.salvar,
                                      prefixo=args.prefixo)
        ok(f"Chave gerada: {priv.n.bit_length()} bits, e={priv.e}")
        if args.salvar:
            ok(f"Salvas em: {args.prefixo}_privada.pem, {args.prefixo}_publica.pem")
        return

    if args.cifrar:
        entrada, saida = args.cifrar
        senha = args.senha or input("  Senha: ")
        n1, n2 = cifrar_ficheiro(entrada, saida, senha)
        ok(f"Ficheiro cifrado: {entrada} ({n1}B) → {saida} ({n2}B)")
        return

    if args.decifrar:
        entrada, saida = args.decifrar
        senha = args.senha or input("  Senha: ")
        try:
            n = decifrar_ficheiro(entrada, saida, senha)
            ok(f"Ficheiro decifrado: {n} bytes → {saida}")
        except ValueError:
            erro("Falha na autenticação — senha incorreta ou ficheiro corrompido.")
        return

    if args.tls:
        inspecionar_tls(args.tls, args.porta)
        return

    if args.todos:
        for k, (_, fn) in MODULOS.items():
            if fn and k != "13":
                try:
                    fn()
                except Exception as e:
                    erro(f"Módulo {k} falhou: {e}")
        return

    if args.modulo:
        if args.modulo == "13":
            host = input("  Host HTTPS: ").strip() or "google.com"
            inspecionar_tls(host, args.porta)
        elif args.modulo in MODULOS:
            _, fn = MODULOS[args.modulo]
            if fn:
                fn()
        else:
            aviso(f"Módulo '{args.modulo}' inválido.")
        return

    # Sem argumentos → menu interativo
    menu()

if __name__ == "__main__":
    cli()
