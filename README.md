# ctf_toolkit

Toolkit Python pensato per challenge in stile OliCyber (crypto, web, network, binary/misc).

## Uso rapido

## Installazione (globale utente)

Dalla root del progetto:

```bash
pip3 install --user --break-system-packages -e .
```

Verifica da qualunque cartella:

```bash
cd /tmp
python3 -c "import ctf_toolkit; print('ok')"
```

Nota: su Debian/Ubuntu recenti il flag `--break-system-packages` e spesso necessario
per installazioni user-level fuori da virtualenv (PEP 668).

Dalla root del workspace (`/home/gabrycoso/olicyber-utilities-1`):

```python
from ctf_toolkit import *
```

Oppure moduli specifici:

```python
from ctf_toolkit.encoding import xor_with_key, single_byte_xor_bruteforce
from ctf_toolkit.crypto_math import modinv, crt, int_nth_root
```

## CLI rapida

```bash
python -m ctf_toolkit xor "ciao" "k"
python -m ctf_toolkit xor "ciao" "k" --hex
python -m ctf_toolkit b64 "hello"
python -m ctf_toolkit b64 "aGVsbG8=" --decode
python -m ctf_toolkit rot "uryyb" -n 13
python -m ctf_toolkit flag "text... flag{demo} ..."
```

## Snippet utili

### 1) Single-byte XOR

```python
from ctf_toolkit import hex_to_bytes, single_byte_xor_bruteforce

ct = hex_to_bytes("1b37373331363f...")
key, pt, score = single_byte_xor_bruteforce(ct)
print(key, pt.decode(errors="ignore"), score)
```

### 2) Repeating-key XOR (keysize guess)

```python
from ctf_toolkit import repeating_key_xor_keysize_guess

best = repeating_key_xor_keysize_guess(cipher_bytes)
print(best[:5])  # [(keysize, distance), ...]
```

### 3) RSA base

```python
from ctf_toolkit import modinv, rsa_decrypt_int, int_to_bytes

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

### 5) DNS exfil da testo Wireshark/tshark

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
    # implementa qui la tua condizione (timing, ordine, risposta html, ecc.)
    ...

secret = bruteforce_secret(printable_charset(), ok, prefix="flag{")
print(secret)
```

### 7) Decrypt chunk `.enc` AES-CBC (come `decr_png.py`)

```python
from ctf_toolkit import decrypt_chunked_aes_cbc_folder

written = decrypt_chunked_aes_cbc_folder(
    enc_folder="to_decr",
    output_folder="decrypted_files",
)
for p in written:
    print("Decrypted:", p)
```

### 8) Ghidra scripting avanzato (wrapper generici)

Dentro uno script Ghidra Python:

```python
from ctf_toolkit import (
    script_args,
    parse_int,
    apply_analysis_options,
    callers_of,
    run_scripts,
)

args = script_args(self)
limit = parse_int(self, args[0] if args else "100", default=100)

apply_analysis_options(self, {
    "ARM Constant Reference Analyzer": "true",
})

for caller in callers_of(self, "00401234")[:limit]:
    self.println(f"caller: {caller}")

run_scripts(self, ["SomeOtherScript.py"], preserve_state=True)
```

### 9) Pattern da script pratici (SQLi/OCR/ARX/decode)

```python
from ctf_toolkit import (
    SQLiApiClient,
    auto_decode_hex_string,
    build_round_ops,
    invert_round_ops_from_hex,
    solve_numeric_captcha_loop,
)

# A) decode multilayer da hex (base64/gzip/zlib/tar)
decoded = auto_decode_hex_string("48656c6c6f")
print(decoded.layers, decoded.decoded)

# B) inversione pipeline byte-ops tipo magicbb
ops = build_round_ops(rounds=500, state_len=36, seed=0x1337)
plain_hex = invert_round_ops_from_hex(
    "1f84e6290b29a50954607fb2ad6615796a522d688d89acffe95a771ce9ba0d12b0288d7c",
    ops,
)
print(plain_hex)

# C) client SQLi JSON generico
client = SQLiApiClient("http://web-17.challs.olicyber.it")
result, error, raw = client.blind("1' AND 1=1 -- ")
print(result, error)

# D) loop captcha numerico con OCR
out = solve_numeric_captcha_loop("http://captcha.challs.olicyber.it", max_steps=150)
print(out["success"], out.get("step"))
```

## Moduli inclusi

- `encoding.py`: base64/base32/base85, hex, rot, xor, hamming, scoring.
- `crypto_math.py`: egcd, modinv, crt, root n-esima, primalita, fattorizzazioni base.
- `chunked_crypto.py`: workflow chunked AES-CBC (`<base>_<idx>.enc`), decrypt/encrypt helpers.
- `challenge_patterns.py`: funzioni generiche da script reali (decode multilayer, SQLi API, OCR captcha, inversione byte-ops).
- `ghidra_tools.py`: helper avanzati e generici per script Ghidra (parse/ask, xref/callers, run scripts, analysis options).
- `io_helpers.py`: I/O, regex flag, parsing numeri/hex da testo rumoroso.
- `networking.py`: recv/send socket, parse DNS query text, reassembly chunk exfil.
- `web.py`: session/retry, payload SQLi base, brute-force generico a prefisso.
- `forensics.py`: entropy, strings, magic bytes, brute-force XOR header.
- `pwn_helpers.py`: pack/unpack, cyclic/cyclic_find, fmt offset probe.

## Nota pratica

## Licenza

Questo progetto e distribuito sotto licenza MIT.
Vedi il file `LICENSE` nella root del repository per il testo completo.

Questa libreria e intentionally leggera e senza dipendenze pesanti extra, per essere pronta subito in ambienti CTF minimali.
