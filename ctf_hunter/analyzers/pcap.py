"""
PCAP analyzer: protocol summary, TCP stream reassembly, HTTP bodies,
credential sniffing, file carving, flag pattern search.
Uses scapy with tshark fallback.
"""
from __future__ import annotations

import re
import base64
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_tshark
from .base import Analyzer


class PcapAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from scapy.all import rdpcap, TCP, UDP, IP, Raw, Ether
            packets = rdpcap(path)
        except Exception as exc:
            # Fallback to tshark summary only
            tshark_data = run_tshark(path)
            if tshark_data:
                findings.append(self._finding(
                    path,
                    f"PCAP parsed via tshark: {len(tshark_data)} packets",
                    str(tshark_data[:5]),
                    severity="INFO",
                    confidence=0.4,
                ))
            else:
                findings.append(self._finding(
                    path,
                    f"PCAP parse error (scapy): {exc}",
                    "",
                    severity="INFO",
                    confidence=0.2,
                ))
            return findings

        # Protocol summary
        findings.extend(self._protocol_summary(path, packets))

        # TCP stream reassembly
        if depth == "deep":
            streams = self._reassemble_tcp(packets)
        else:
            streams = self._reassemble_tcp_fast(packets)

        # HTTP extraction
        findings.extend(self._extract_http(path, streams, flag_pattern))

        # Credential sniffing
        findings.extend(self._sniff_credentials(path, streams, flag_pattern))

        # Flag pattern in all payloads
        findings.extend(self._search_payloads(path, packets, flag_pattern))

        if depth == "deep":
            # File carving
            findings.extend(self._carve_files(path, streams, flag_pattern))

        return findings

    # ------------------------------------------------------------------

    def _protocol_summary(self, path: str, packets) -> List[Finding]:
        try:
            from scapy.all import IP, TCP, UDP, ICMP
        except Exception:
            return []
        proto_counts: Counter = Counter()
        for pkt in packets:
            if pkt.haslayer("TCP"):
                proto_counts["TCP"] += 1
            elif pkt.haslayer("UDP"):
                proto_counts["UDP"] += 1
            elif pkt.haslayer("ICMP"):
                proto_counts["ICMP"] += 1
            else:
                proto_counts["Other"] += 1
        summary = ", ".join(f"{k}:{v}" for k, v in proto_counts.most_common())
        return [self._finding(
            path,
            f"PCAP protocol summary: {len(packets)} packets",
            summary,
            severity="INFO",
            confidence=0.5,
        )]

    def _reassemble_tcp(self, packets) -> dict[tuple, bytes]:
        """Full TCP stream reassembly keyed by (src_ip, src_port, dst_ip, dst_port)."""
        streams: dict[tuple, bytes] = defaultdict(bytes)
        try:
            from scapy.all import TCP, IP, Raw
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                    key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                    streams[key] += bytes(pkt[Raw].load)
        except Exception:
            pass
        return dict(streams)

    def _reassemble_tcp_fast(self, packets) -> dict[tuple, bytes]:
        """Fast mode: only first 100 packets per stream, limited to 4096 bytes."""
        streams: dict[tuple, bytes] = defaultdict(bytes)
        stream_counts: Counter = Counter()
        try:
            from scapy.all import TCP, IP, Raw
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                    key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                    if stream_counts[key] < 100 and len(streams[key]) < 4096:
                        streams[key] += bytes(pkt[Raw].load)
                        stream_counts[key] += 1
        except Exception:
            pass
        return dict(streams)

    def _extract_http(
        self, path: str, streams: dict, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        for key, data in streams.items():
            text = data.decode("latin-1", errors="replace")
            # Find HTTP requests
            for m in re.finditer(r"(GET|POST|PUT|DELETE|HEAD) (.+?) HTTP/[\d.]+", text):
                method, uri = m.group(1), m.group(2)
                findings.append(self._finding(
                    path,
                    f"HTTP {method} request: {uri[:100]}",
                    f"Stream {key[0]}:{key[1]} → {key[2]}:{key[3]}",
                    severity="INFO",
                    confidence=0.5,
                ))
            # Flag in HTTP body
            if self._check_flag(text, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Flag pattern in HTTP stream {key[0]}→{key[2]}",
                    text[:500],
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
        return findings

    def _sniff_credentials(
        self, path: str, streams: dict, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        for key, data in streams.items():
            text = data.decode("latin-1", errors="replace")
            # Basic Auth
            for m in re.finditer(r"Authorization: Basic ([A-Za-z0-9+/=]+)", text):
                try:
                    creds = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                    findings.append(self._finding(
                        path,
                        f"HTTP Basic Auth credentials in stream",
                        f"Credentials: {creds}",
                        severity="HIGH",
                        flag_match=self._check_flag(creds, flag_pattern),
                        confidence=0.90,
                    ))
                except Exception:
                    pass
            # FTP
            for m in re.finditer(r"(?:USER|PASS) ([^\r\n]+)", text, re.IGNORECASE):
                findings.append(self._finding(
                    path,
                    f"FTP credential in stream: {m.group(0)[:80]}",
                    str(key),
                    severity="HIGH",
                    confidence=0.85,
                ))
            # HTTP form POST
            for m in re.finditer(r"(?:password|passwd|pwd)=([^&\r\n]+)", text, re.IGNORECASE):
                findings.append(self._finding(
                    path,
                    f"HTTP form password in stream: {m.group(0)[:80]}",
                    str(key),
                    severity="HIGH",
                    confidence=0.85,
                ))
        return findings

    def _search_payloads(
        self, path: str, packets, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from scapy.all import Raw
            for i, pkt in enumerate(packets):
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    text = payload.decode("latin-1", errors="replace")
                    if self._check_flag(text, flag_pattern):
                        findings.append(self._finding(
                            path,
                            f"Flag pattern in packet #{i} payload",
                            text[:300],
                            severity="HIGH",
                            flag_match=True,
                            confidence=0.95,
                        ))
        except Exception:
            pass
        return findings

    def _carve_files(
        self, path: str, streams: dict, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        _FILE_SIGS = {
            b"\x89PNG\r\n\x1a\n": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"PK\x03\x04": "ZIP",
            b"\x1f\x8b": "gzip",
            b"%PDF": "PDF",
        }
        for key, data in streams.items():
            for sig, file_type in _FILE_SIGS.items():
                if sig in data:
                    idx = data.index(sig)
                    findings.append(self._finding(
                        path,
                        f"Carved {file_type} file from TCP stream {key[0]}→{key[2]}",
                        f"Signature at byte offset {idx} in stream",
                        severity="HIGH",
                        confidence=0.80,
                    ))
        return findings
