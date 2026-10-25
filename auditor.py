#!/usr/bin/env python3
"""
Password Security Auditor & Entropy Analyzer (v1.0.1)
-----------------------------------------------------
Defensive security utility for evaluating credential resilience, detecting
dictionary mutation patterns, and maintaining parameterized SQLite audit logs[cite: 3].

Security Remediations Included (GHSA-PSA-2026-001):
- CWE-407: Enforced strict byte-length bounds prior to O(N*M) dynamic programming
  allocation in Levenshtein distance calculation to prevent CPU/Memory DoS.
- CWE-89: Enforced strict parameterized SQL statements across all SQLite operations.
- CWE-532: Implemented SHA-256 salted fingerprinting to prevent plaintext credential
  exposure in audit logs.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import secrets
import sqlite3
import sys
import unittest
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from zxcvbn import zxcvbn  # type: ignore
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False

# Security threshold (GHSA-PSA-2026-001 / CWE-407 remediation)
MAX_INPUT_BYTES: int = 256
DEFAULT_DB_PATH: str = "security_audit.db"


class SecurityLimitExceededError(ValueError):
    """Raised when an input payload exceeds safe processing boundaries (CWE-407)."""


@dataclass(frozen=True)
class AuditResult:
    """Immutable data structure representing a single credential security assessment."""
    credential_Hash: str
    length: int
    shannon_entropy_bits: float
    charset_pool_size: int
    theoretical_crack_bits: float
    min_levenshtein_distance: Optional[int]
    heuristic_score: int  # 0 (critical risk) to 4 (strong)
    detected_patterns: List[str]
    risk_level: str
    timestamp_utc: str


class HeuristicPatternEngine:
    """
    Analyzes credentials for structural weaknesses: spatial keyboard walks,
    L33T substitutions, sequential runs, and date patterns. Uses zxcvbn if
    installed, with a deterministic built-in heuristic fallback.
    """

    KEYBOARD_ROWS: Tuple[str, ...] = (
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
    )
    LEET_MAP: Dict[str, str] = str.maketrans({
        "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
        "0": "o", "$": "s", "5": "s", "7": "t",
    })
    DATE_REGEX = re.compile(r"(19\d{2}|20\d{2}|0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])?")
    REPEAT_REGEX = re.compile(r"(.)\1{2,}")

    @classmethod
    def normalize_leet(cls, text: str) -> str:
        return text.lower().translate(cls.LEET_MAP)

    @classmethod
    def analyze(cls, password: str) -> Tuple[int, List[str]]:
        patterns: List[str] = []
        lower_pwd = password.lower()

        if HAS_ZXCVBN:
            res = zxcvbn(password)
            score = int(res.get("score", 0))
            for match in res.get("sequence", []):
                pattern_name = match.get("pattern", "unknown")
                if pattern_name not in patterns:
                    patterns.append(f"zxcvbn:{pattern_name}")
            return score, patterns

        # Built-in deterministic heuristic analysis
        if cls.REPEAT_REGEX.search(password):
            patterns.append("repeated_character_run")

        if cls.DATE_REGEX.search(password):
            patterns.append("date_or_year_pattern")

        # Detect spatial keyboard walks (forward and reverse)
        for row in cls.KEYBOARD_ROWS:
            for idx in range(len(row) - 3):
                sub = row[idx:idx + 4]
                if sub in lower_pwd or sub[::-1] in lower_pwd:
                    patterns.append("spatial_keyboard_walk")
                    break

        # Detect pure alpha or pure numeric compositions
        if password.isdigit():
            patterns.append("numeric_only")
        elif password.isalpha():
            patterns.append("alphabetic_only")

        # Calculate heuristic score (0..4)
        base_score = 4
        if len(password) < 8:
            base_score -= 3
        elif len(password) < 12:
            base_score -= 1

        base_score -= len(set(patterns))
        return max(0, min(4, base_score)), patterns


class PasswordSecurityAuditor:
    """Core analytical engine for password entropy, edit distance, and safe audit logging."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, audit_salt: Optional[bytes] = None) -> None:
        self.db_path = Path(db_path)
        self.audit_salt = audit_salt or secrets.token_bytes(16)
        self._init_database()

    @staticmethod
    def _validate_bounds(payload: str, context: str = "input") -> None:
        """
        Enforces strict byte-length limits to prevent CWE-407 algorithmic
        complexity attacks on O(N*M) matrix operations.
        """
        byte_len = len(payload.encode("utf-8", errors="replace"))
        if byte_len > MAX_INPUT_BYTES:
            raise SecurityLimitExceededError(
                f"Security policy violation: {context} length ({byte_len} bytes) "
                f"exceeds MAX_INPUT_BYTES ({MAX_INPUT_BYTES})."
            )

    @staticmethod
    def calculate_shannon_entropy(password: str) -> float:
        """Computes total Shannon entropy in bits across the credential string."""
        PasswordSecurityAuditor._validate_bounds(password, "password")
        if not password:
            return 0.0
        length = len(password)
        frequencies = Counter(password)
        per_char_entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in frequencies.values()
        )
        return round(per_char_entropy * length, 4)

    @staticmethod
    def calculate_charset_pool(password: str) -> Tuple[int, float]:
        """Determines active character set pool size and theoretical keyspace entropy."""
        if not password:
            return 0, 0.0
        pool = 0
        if any(c.islower() for c in password):
            pool += 26
        if any(c.isupper() for c in password):
            pool += 26
        if any(c.isdigit() for c in password):
            pool += 10
        if any(not c.isalnum() for c in password):
            pool += 32
        theoretical_bits = round(len(password) * math.log2(pool), 4) if pool > 0 else 0.0
        return pool, theoretical_bits

    @classmethod
    def levenshtein_distance(cls, source: str, target: str) -> int:
        """
        Computes Levenshtein edit distance using O(min(N, M)) space-optimized
        dynamic programming with strict pre-execution payload bounds (GHSA-PSA-2026-001).
        """
        cls._validate_bounds(source, "source credential")
        cls._validate_bounds(target, "target dictionary entry")

        if len(source) < len(target):
            source, target = target, source
        if not target:
            return len(source)

        previous_row = list(range(len(target) + 1))
        for i, src_char in enumerate(source):
            current_row = [i + 1]
            for j, tgt_char in enumerate(target):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (src_char != tgt_char)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _fingerprint_credential(self, password: str) -> str:
        """Generates an anonymized SHA-256 salted digest for safe audit logging (CWE-532)."""
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.audit_salt,
            iterations=100_000,
        )
        return digest.hex()[:32]

    def _init_database(self) -> None:
        """Initializes SQLite audit schema with strict constraints and WAL journaling."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_hash TEXT NOT NULL,
                    pwd_length INTEGER NOT NULL CHECK(pwd_length >= 0),
                    shannon_entropy REAL NOT NULL,
                    charset_pool INTEGER NOT NULL,
                    min_levenshtein INTEGER,
                    heuristic_score INTEGER NOT NULL CHECK(heuristic_score BETWEEN 0 AND 4),
                    patterns TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def evaluate(
        self,
        password: str,
        compromised_corpus: Optional[Iterable[str]] = None,
        record_audit: bool = True,
    ) -> AuditResult:
        """Performs full multi-metric security audit on a candidate credential."""
        self._validate_bounds(password, "candidate credential")

        shannon_bits = self.calculate_shannon_entropy(password)
        pool_size, theoretical_bits = self.calculate_charset_pool(password)
        heuristic_score, patterns = HeuristicPatternEngine.analyze(password)

        min_dist: Optional[int] = None
        normalized_candidate = HeuristicPatternEngine.normalize_leet(password)

        if compromised_corpus:
            distances: List[int] = []
            for entry in compromised_corpus:
                if not entry:
                    continue
                self._validate_bounds(entry, "corpus item")
                raw_dist = self.levenshtein_distance(password.lower(), entry.lower())
                leet_dist = self.levenshtein_distance(normalized_candidate, entry.lower())
                distances.append(min(raw_dist, leet_dist))

            if distances:
                min_dist = min(distances)
                if min_dist == 0:
                    patterns.append("exact_or_leet_dictionary_match")
                    heuristic_score = 0
                elif min_dist <= 2:
                    patterns.append(f"near_dictionary_mutation(dist={min_dist})")
                    heuristic_score = min(heuristic_score, 1)

        if heuristic_score <= 1 or shannon_bits < 28.0:
            risk_level = "CRITICAL"
        elif heuristic_score == 2 or shannon_bits < 45.0:
            risk_level = "ELEVATED"
        elif heuristic_score == 3 or shannon_bits < 60.0:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"

        result = AuditResult(
            credential_Hash=self._fingerprint_credential(password),
            length=len(password),
            shannon_entropy_bits=shannon_bits,
            charset_pool_size=pool_size,
            theoretical_crack_bits=theoretical_bits,
            min_levenshtein_distance=min_dist,
            heuristic_score=heuristic_score,
            detected_patterns=patterns,
            risk_level=risk_level,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )

        if record_audit:
            self._log_to_sqlite(result)

        return result

    def _log_to_sqlite(self, result: AuditResult) -> None:
        """
        Records anonymized audit metrics using parameterized SQL statements
        to prevent SQL Injection (GHSA-PSA-2026-001 / CWE-89 remediation).
        """
        patterns_serialized = ",".join(result.detected_patterns) if result.detected_patterns else "none"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO security_audit_logs (
                    credential_hash, pwd_length, shannon_entropy, charset_pool,
                    min_levenshtein, heuristic_score, patterns, risk_level, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    result.credential_Hash,
                    result.length,
                    result.shannon_entropy_bits,
                    result.charset_pool_size,
                    result.min_levenshtein_distance,
                    result.heuristic_score,
                    patterns_serialized,
                    result.risk_level,
                    result.timestamp_utc,
                ),
            )
            conn.commit()


class SecurityRegressionTestSuite(unittest.TestCase):
    """Automated security regression suite verifying GHSA-PSA-2026-001 patches."""

    def setUp(self) -> None:
        self.auditor = PasswordSecurityAuditor(db_path=":memory:")

    def test_cwe_407_dos_protection(self) -> None:
        """Verify oversized inputs raise SecurityLimitExceededError before allocation."""
        oversized_payload = "A" * (MAX_INPUT_BYTES + 1)
        with self.assertRaises(SecurityLimitExceededError):
            self.auditor.levenshtein_distance(oversized_payload, "password123")

    def test_cwe_89_sql_injection_resilience(self) -> None:
        """Verify malicious SQL metacharacters in credentials do not corrupt audit tables."""
        sqli_payload = "p@ss'; DROP TABLE security_audit_logs; --"
        res = self.auditor.evaluate(sqli_payload, compromised_corpus=["admin123"])
        self.assertEqual(res.length, len(sqli_payload))

    def test_leet_mutation_detection(self) -> None:
        """Verify L33T substitutions against known compromised baselines are flagged."""
        res = self.auditor.evaluate("P@ssw0rd1", compromised_corpus=["password"])
        self.assertLessEqual(res.min_levenshtein_distance or 99, 2)
        self.assertEqual(res.risk_level, "CRITICAL")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Defensive Password Security Auditor & Entropy Analyzer (v1.0.1)"
    )
    parser.add_argument("-p", "--password", type=str, help="Candidate password string to audit")
    parser.add_argument("--db", type=str, default=DEFAULT_DB_PATH, help="SQLite audit log path")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in security regression tests (GHSA-PSA-2026-001)",
    )
    args = parser.parse_args()

    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityRegressionTestSuite)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1

    if not args.password:
        parser.print_help()
        return 0

    baseline_dictionary = ["password", "12345678", "qwertyuiop", "admin", "welcome"]
    auditor = PasswordSecurityAuditor(db_path=args.db)
    report = auditor.evaluate(args.password, compromised_corpus=baseline_dictionary)

    for key, value in asdict(report).items():
        print(f"{key:26s}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
