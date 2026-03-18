#!/usr/bin/env python3
"""Unified CLI, demo, and self-test runner for auto-decrypt hex strings."""

import argparse
from pathlib import Path

from ctf_toolkit.encoding import (
    auto_decrypt_hex,
    bytes_to_hex,
    detect_hex_encryption,
    rot_n,
    xor_with_key,
)


def format_result(result, verbose=False):
    """Format a single decryption result for display."""
    lines = []
    lines.append(f"  Method: {result.method}")
    lines.append(f"  Key: {result.key if result.key else '(none)'}")
    lines.append(f"  Confidence: {result.confidence:.1%}")
    
    if verbose:
        lines.append(f"  Raw bytes: {result.plaintext.hex()[:80]}")
    
    if result.readable_text:
        text = result.readable_text
        if len(text) > 100:
            text = text[:97] + "..."
        lines.append(f"  Result: {text}")
    else:
        lines.append(f"  Result: (binary data)")
    
    return "\n".join(lines)


def cmd_decrypt(hex_string, top_n=5, verbose=False):
    """Decrypt a hex string and show results."""
    print(f"\nInput: {hex_string[:60]}{'...' if len(hex_string) > 60 else ''}")
    print(f"Length: {len(hex_string)} chars -> {len(hex_string)//2} bytes")
    
    try:
        results = auto_decrypt_hex(hex_string, top_n=top_n)
        
        if not results:
            print("\nNo decryption results found.")
            return False
        
        print(f"\nFound {len(results)} result(s):\n")
        
        for i, result in enumerate(results, 1):
            confidence_bar = "=" * int(result.confidence * 20)
            print(f"#{i} [{confidence_bar:20}] {result.confidence:5.1%}")
            print(format_result(result, verbose))
            print()
        
        return True
        
    except ValueError as e:
        print(f"\nError: {e}")
        return False


def cmd_analyze(hex_string):
    """Analyze encryption characteristics of a hex string."""
    print(f"\nAnalyzing: {hex_string[:60]}{'...' if len(hex_string) > 60 else ''}")
    
    try:
        analysis = detect_hex_encryption(hex_string)
        
        print("\nAnalysis Results:")
        print(f"  - Likely encrypted: {'YES' if analysis['is_encrypted'] else 'NO'}")
        print(f"  - Entropy: {analysis['entropy']:.2f}/8.00", end="")
        
        if analysis['entropy'] < 3:
            print(" (very predictable)")
        elif analysis['entropy'] < 5:
            print(" (somewhat random)")
        else:
            print(" (highly random)")
        
        print(f"  - Printable ratio: {analysis['printable_ratio']:.1%}")
        print(f"  - Detection confidence: {analysis['confidence']:.1%}")
        print(f"  - Plaintext confidence: {analysis['plaintext_confidence']:.1%}")
        
        if analysis['likely_methods']:
            print(f"  - Suggested methods: {', '.join(analysis['likely_methods'])}")
        else:
            print(f"  - Suggested methods: (try all available)")
        
    except ValueError as e:
        print(f"\nError: {e}")


def cmd_file(filename, top_n=5, verbose=False):
    """Decrypt hex from a file (one per line)."""
    path = Path(filename)
    
    if not path.exists():
        print(f"File not found: {filename}")
        return
    
    print(f"Reading from: {filename}\n")
    
    with open(path, 'r') as f:
        for line_no, line in enumerate(f, 1):
            hex_str = line.strip()
            
            if not hex_str or hex_str.startswith("#"):
                continue
            
            print(f"--- Line {line_no} ---")
            cmd_decrypt(hex_str, top_n=top_n, verbose=verbose)


def demo_basic():
    print("\n" + "=" * 70)
    print("DEMO 1: Basic Decryption")
    print("=" * 70)

    hex_data = "0a272e2e2d6e6201160462152d302e2663"
    print(f"\nMystery hex: {hex_data}")

    results = auto_decrypt_hex(hex_data, top_n=3)
    print("\nAuto-decrypt results:")
    for i, res in enumerate(results, 1):
        bar = "=" * int(res.confidence * 20)
        text = (res.readable_text or "(binary)")[:40]
        print(f"  {i}. [{bar:20}] {res.confidence:5.1%} | {res.method:20} | {text}")


def demo_detection():
    print("\n" + "=" * 70)
    print("DEMO 2: Encryption Detection")
    print("=" * 70)

    test_cases = [
        ("Plaintext", b"Hello World"),
        ("XOR 0x42", bytes(b ^ 0x42 for b in b"Hello")),
        ("XOR 0xFF", bytes(b ^ 0xFF for b in b"Secret")),
    ]

    for name, data in test_cases:
        hex_str = bytes_to_hex(data)
        analysis = detect_hex_encryption(hex_str)
        print(f"\n{name}:")
        print(f"  Encrypted: {analysis['is_encrypted']}")
        print(f"  Entropy: {analysis['entropy']:.2f}/8.00")
        print(f"  Printable: {analysis['printable_ratio']:.1%}")
        print(f"  Confidence: {analysis['confidence']:.1%}")


def demo_batch():
    print("\n" + "=" * 70)
    print("DEMO 3: Batch Processing")
    print("=" * 70)

    hex_list = [
        ("Test 1", "48656c6c6f"),
        ("Test 2", "0a272e2e2d6e62"),
        ("Test 3", bytes_to_hex(bytes(b ^ 0xFF for b in b"Flag"))),
    ]

    print("\nProcessing multiple hex strings:\n")
    for name, hex_str in hex_list:
        try:
            results = auto_decrypt_hex(hex_str, top_n=1)
            if results:
                r = results[0]
                text = (r.readable_text or "(binary)")[:30]
                print(f"  {name:10} -> {text:30} ({r.confidence:.1%})")
        except Exception:
            print(f"  {name:10} -> ERROR")


def run_demo_suite() -> bool:
    print("\n" + "=" * 70)
    print("AUTO-DECRYPT SYSTEM - INTERACTIVE DEMO")
    print("=" * 70)

    try:
        demo_basic()
        demo_detection()
        demo_batch()
        print("\n" + "=" * 70)
        print("Demo completed!")
        print("=" * 70 + "\n")
        return True
    except Exception as exc:
        print(f"\nFAIL: Demo error: {exc}")
        return False


def test_plaintext_detection():
    print("\n" + "=" * 60)
    print("TEST 1: Plaintext Detection")
    print("=" * 60)

    plaintext = b"This is a normal message that is not encrypted at all!"
    hex_plain = bytes_to_hex(plaintext)

    print(f"Original: {plaintext}")
    print(f"Hex: {hex_plain}")

    result = detect_hex_encryption(hex_plain)
    print("\nAnalysis:")
    print(f"  Is encrypted: {result['is_encrypted']}")
    print(f"  Entropy: {result['entropy']:.2f}")
    print(f"  Printable ratio: {result['printable_ratio']:.1%}")

    results = auto_decrypt_hex(hex_plain, top_n=1)
    print("\nBest result:")
    print(f"  Method: {results[0].method}")
    print(f"  Confidence: {results[0].confidence:.1%}")
    print(f"  Text: {results[0].readable_text}")


def test_single_xor():
    print("\n" + "=" * 60)
    print("TEST 2: Single-Byte XOR")
    print("=" * 60)

    plaintext = b"Hello, CTF World!"
    key = 0x42
    ciphertext = bytes(b ^ key for b in plaintext)
    hex_cipher = bytes_to_hex(ciphertext)

    print(f"Original: {plaintext}")
    print(f"Key: 0x{key:02x}")
    print(f"Hex cipher: {hex_cipher}")

    results = auto_decrypt_hex(hex_cipher, top_n=1)
    print("\nBest result:")
    print(f"  Method: {results[0].method}")
    print(f"  Key: {results[0].key}")
    print(f"  Confidence: {results[0].confidence:.1%}")
    print(f"  Text: {results[0].readable_text}")


def test_xor_mask():
    print("\n" + "=" * 60)
    print("TEST 3: XOR Mask (0xFF)")
    print("=" * 60)

    plaintext = b"Flag{xor_is_easy}"
    key = 0xFF
    ciphertext = bytes(b ^ key for b in plaintext)
    hex_cipher = bytes_to_hex(ciphertext)

    print(f"Original: {plaintext}")
    print(f"XOR Key: 0x{key:02x}")
    print(f"Hex cipher: {hex_cipher}")

    results = auto_decrypt_hex(hex_cipher, top_n=1)
    print("\nBest result:")
    print(f"  Method: {results[0].method}")
    print(f"  Confidence: {results[0].confidence:.1%}")
    print(f"  Text: {results[0].readable_text}")


def test_caesar():
    print("\n" + "=" * 60)
    print("TEST 4: Caesar Cipher (ROT-5)")
    print("=" * 60)

    plaintext = "TheCTFisAwesome"
    ciphertext = rot_n(plaintext, 5)
    hex_cipher = bytes_to_hex(ciphertext.encode())

    print(f"Original: {plaintext}")
    print(f"ROT-5 cipher: {ciphertext}")
    print(f"Hex cipher: {hex_cipher}")

    results = auto_decrypt_hex(hex_cipher, top_n=2)
    print("\nTop results:")
    for i, res in enumerate(results[:2], 1):
        print(f"  {i}. Method: {res.method}, Confidence: {res.confidence:.1%}, Text: {res.readable_text}")


def test_repeating_xor():
    print("\n" + "=" * 60)
    print("TEST 5: Repeating-Key XOR")
    print("=" * 60)

    plaintext = b"The quick brown fox jumps over the lazy dog. " * 3
    key = b"SECRET"
    ciphertext = xor_with_key(plaintext, key)
    hex_cipher = bytes_to_hex(ciphertext)

    print(f"Original (len={len(plaintext)}): {plaintext[:50]}...")
    print(f"Key: {key}")
    print(f"Hex cipher (first 100 chars): {hex_cipher[:100]}...")

    results = auto_decrypt_hex(hex_cipher, top_n=1)
    print("\nBest result:")
    print(f"  Method: {results[0].method}")
    print(f"  Confidence: {results[0].confidence:.1%}")
    text = results[0].readable_text[:60] if results[0].readable_text else "(binary)"
    print(f"  Text: {text}")


def run_test_suite() -> bool:
    print("\n" + "=" * 60)
    print("AUTO-DECRYPT HEXADECIMAL SYSTEM TEST SUITE")
    print("=" * 60)

    try:
        test_plaintext_detection()
        test_single_xor()
        test_xor_mask()
        test_caesar()
        test_repeating_xor()

        print("\n" + "=" * 60)
        print("PASS: All tests completed successfully!")
        print("=" * 60 + "\n")
        return True
    except Exception as exc:
        print(f"\nFAIL: Test failed: {exc}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Auto-decrypt hexadecimal strings (CLI + demo + self-test)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("hex", nargs="?", help="Hex string to decrypt")
    parser.add_argument("--analyze", "-a", action="store_true", help="Only analyze (don't decrypt)")
    parser.add_argument("--file", "-f", metavar="FILE", help="Read hex strings from file")
    parser.add_argument("--demo", action="store_true", help="Run interactive demo suite")
    parser.add_argument("--test", action="store_true", help="Run self-test suite")
    parser.add_argument("-n", "--top", type=int, default=5, metavar="N", help="Show top N results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.demo:
        ok = run_demo_suite()
        raise SystemExit(0 if ok else 1)
    elif args.test:
        ok = run_test_suite()
        raise SystemExit(0 if ok else 1)
    elif args.file:
        cmd_file(args.file, top_n=args.top, verbose=args.verbose)
    elif args.analyze and args.hex:
        cmd_analyze(args.hex)
    elif args.hex:
        cmd_decrypt(args.hex, top_n=args.top, verbose=args.verbose)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
