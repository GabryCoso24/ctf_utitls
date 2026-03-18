# ctf_toolkit

Toolkit Python per challenge CTF stile OliCyber: crypto, web, networking, forensics, pwn e automazioni pratiche.

Questo e l'unico file di documentazione del progetto.

## Installazione

Dal root del progetto:

```bash
pip3 install --user --break-system-packages -e .
```

Verifica rapida:

```bash
python3 -c "import ctf_toolkit; print('ok')"
```

## Quick Start

Import completo:

```python
from ctf_toolkit import *
```

Import mirato:

```python
from ctf_toolkit.encoding import (
    auto_decrypt_hex,
    detect_hex_encryption,
    single_byte_xor_bruteforce,
    xor_with_key,
)
from ctf_toolkit.crypto_math import crt, int_nth_root, modinv
```

## CLI Rapida

CLI principale:

```bash
python -m ctf_toolkit xor "hello" "key"
python -m ctf_toolkit xor "hello" "key" --hex
python -m ctf_toolkit b64 "hello"
python -m ctf_toolkit b64 "aGVsbG8=" --decode
python -m ctf_toolkit rot "uryyb" -n 13
python -m ctf_toolkit flag "text... flag{demo} ..."
```

CLI auto-decrypt hex:

```bash
python -m ctf_toolkit.hex_decrypt_cli "0a272e2e2d6e6201160462152d302e2663"
python -m ctf_toolkit.hex_decrypt_cli --analyze "3c2b39041913"
python -m ctf_toolkit.hex_decrypt_cli --file data.txt
python -m ctf_toolkit.hex_decrypt_cli -n 10 "0a272e2e"
python -m ctf_toolkit.hex_decrypt_cli -v "0a272e2e"
python -m ctf_toolkit.hex_decrypt_cli --demo
python -m ctf_toolkit.hex_decrypt_cli --test
```

## Nuovo: Auto-Decrypt Hex

La parte nuova del toolkit permette di analizzare e decifrare stringhe hex automaticamente, senza chiave fornita.

Funzioni principali in `ctf_toolkit.encoding`:

- `detect_hex_encryption(hex_string)`
- `auto_decrypt_hex(hex_string, top_n=5)`
- `DecryptionResult`

Capacita supportate:

- Riconoscimento plaintext
- XOR single-byte automatico
- Tentativi repeating-key XOR
- Caesar/ROT-N
- XOR mask comuni (`0xFF`, `0xAA`, `0x55`, ecc.)
- Ranking risultati per confidence

Esempio base:

```python
from ctf_toolkit.encoding import auto_decrypt_hex, detect_hex_encryption

hex_data = "0a272e2e2d6e6201160462152d302e2663"

analysis = detect_hex_encryption(hex_data)
print("is_encrypted:", analysis["is_encrypted"])
print("entropy:", round(analysis["entropy"], 3))
print("confidence:", round(analysis["confidence"], 3))

results = auto_decrypt_hex(hex_data, top_n=3)
for r in results:
    print(r.method, r.key, f"{r.confidence:.1%}", r.readable_text)
```

`detect_hex_encryption` restituisce:

- `is_encrypted`: bool
- `entropy`: float (0..8)
- `printable_ratio`: float (0..1)
- `likely_methods`: list[str]
- `confidence`: float (0..1)
- `plaintext_confidence`: float (0..1)

## Esempi Utili

### 1) Single-byte XOR brute force

```python
from ctf_toolkit import hex_to_bytes, single_byte_xor_bruteforce

ct = hex_to_bytes("1b37373331363f...")
key, pt, score = single_byte_xor_bruteforce(ct)
print(key, pt.decode(errors="ignore"), score)
```

### 2) Repeating-key XOR keysize guess

```python
from ctf_toolkit import repeating_key_xor_keysize_guess

best = repeating_key_xor_keysize_guess(cipher_bytes)
print(best[:5])
```

### 3) RSA base

```python
from ctf_toolkit import int_to_bytes, modinv, rsa_decrypt_int

d = modinv(e, phi)
m = rsa_decrypt_int(c, d, n)
print(int_to_bytes(m))
```

### 4) CRT + low exponent

```python
from ctf_toolkit import crt, int_nth_root, int_to_bytes

x, mod = crt([c1, c2, c3], [n1, n2, n3])
m, exact = int_nth_root(x, 3)
if exact:
    print(int_to_bytes(m))
```

### 5) DNS exfil parsing

```python
from ctf_toolkit import parse_dns_qnames_from_text, reassemble_subdomain_hex

text = open("dns.txt", "r", encoding="utf-8").read()
qnames = parse_dns_qnames_from_text(text)
raw = reassemble_subdomain_hex(qnames, domain_suffix="attacker.eve")
print(raw)
```

### 6) Brute-force prefisso (oracle)

```python
from ctf_toolkit import bruteforce_secret, printable_charset

def ok(prefix: str) -> bool:
    return True

secret = bruteforce_secret(printable_charset(), ok, prefix="flag{")
print(secret)
```

### 7) Decrypt chunk `.enc` AES-CBC

```python
from ctf_toolkit import decrypt_chunked_aes_cbc_folder

written = decrypt_chunked_aes_cbc_folder(
    enc_folder="to_decr",
    output_folder="decrypted_files",
)
for p in written:
    print("Decrypted:", p)
```

### 8) Ghidra scripting helper

```python
from ctf_toolkit import (
    apply_analysis_options,
    callers_of,
    parse_int,
    run_scripts,
    script_args,
)

args = script_args(self)
limit = parse_int(self, args[0] if args else "100", default=100)

apply_analysis_options(self, {"ARM Constant Reference Analyzer": "true"})

for caller in callers_of(self, "00401234")[:limit]:
    self.println(f"caller: {caller}")

run_scripts(self, ["SomeOtherScript.py"], preserve_state=True)
```

### 9) Pattern pratici (SQLi/OCR/ARX/decode)

```python
from ctf_toolkit import (
    SQLiApiClient,
    auto_decode_hex_string,
    build_round_ops,
    invert_round_ops_from_hex,
    solve_numeric_captcha_loop,
)

decoded = auto_decode_hex_string("48656c6c6f")
print(decoded.layers, decoded.decoded)

ops = build_round_ops(rounds=500, state_len=36, seed=0x1337)
plain_hex = invert_round_ops_from_hex(
    "1f84e6290b29a50954607fb2ad6615796a522d688d89acffe95a771ce9ba0d12b0288d7c",
    ops,
)
print(plain_hex)

client = SQLiApiClient("http://web-17.challs.olicyber.it")
result, error, raw = client.blind("1' AND 1=1 -- ")
print(result, error)

out = solve_numeric_captcha_loop("http://captcha.challs.olicyber.it", max_steps=150)
print(out["success"], out.get("step"))
```

## Test e Demo Auto-Decrypt

```bash
python -m ctf_toolkit.hex_decrypt_cli --test
python -m ctf_toolkit.hex_decrypt_cli --demo
```

## Feature Overview

### Encoding / Decoding

- Hex, Base64, Base32, Base85
- XOR (single-byte, repeating-key)
- ROT-N
- Hamming distance e helper bytes
- Auto-detect + auto-decrypt di stringhe hex

### Crypto / Number Theory

- RSA encrypt/decrypt integer
- CRT
- EGCD e modular inverse
- Integer nth root
- Fermat e Pollard Rho
- Primality testing

### Pwn

- `p8/p16/p32/p64`, `u16/u32/u64`
- De Bruijn `cyclic` / `cyclic_find`
- Format-string offset probe

### Forensics

- Magic bytes e filetype detection
- Entropia Shannon
- ASCII strings extraction
- XOR header bruteforce

### Networking

- TCP/UDP helper
- DNS query parsing da dump testuali
- Reassembly subdomain hex

### Web

- Session/retry helper
- Payload SQLi base
- Prefix brute-force/oracle helper

### Challenge Patterns

- Auto decode multilayer (base64/zlib/gzip/tar)
- Round ops scheduling/inversion
- Utility per challenge realistiche

## Moduli Inclusi

- `encoding.py`: encoding bytes + auto-decrypt hex.
- `crypto_math.py`: aritmetica modulare, CRT, RSA.
- `chunked_crypto.py`: workflow file chunked AES-CBC.
- `challenge_patterns.py`: pattern multi-step da challenge reali.
- `forensics.py`: magic bytes, entropy, stringhe.
- `networking.py`: socket helper e parsing DNS.
- `pwn_helpers.py`: helper pwn/packing/pattern.
- `web.py`: helper HTTP/web challenge.
- `ghidra_tools.py`: helper generici per script Ghidra.
- `io_helpers.py`: I/O e parsing testo rumoroso.

## Struttura Progetto

```text
ctf_toolkit/
├── __init__.py
├── __main__.py
├── encoding.py
├── crypto_math.py
├── chunked_crypto.py
├── challenge_patterns.py
├── forensics.py
├── networking.py
├── pwn_helpers.py
├── web.py
├── ghidra_tools.py
├── io_helpers.py
└── hex_decrypt_cli.py
```

## Licenza

MIT. Vedi [LICENSE](LICENSE).
