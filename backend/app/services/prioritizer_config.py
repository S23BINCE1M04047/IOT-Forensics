"""All tunable thresholds in one place. Change values here, never inside rule logic."""
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.config import BASE_DIR

RULESET_VERSION = "v1.0"


@dataclass(frozen=True)
class PrioritizerConfig:
    # --- data files ---
    whitelist_path: Path = BASE_DIR / "data" / "whitelist.json"
    threat_intel_path: Path = BASE_DIR / "data" / "threat_intel.csv"

    # --- R-BEACON-01 ---
    beacon_min_repetitions: int = 5          # minimum number of contact events
    beacon_max_cv: float = 0.2               # population stdev / mean of inter-event gaps
    beacon_burst_gap_s: float = 1.0          # packets closer than this belong to one event
    beacon_ignore_protocols: tuple[str, ...] = ("ARP",)

    # --- R-DNS-LONG-01 ---
    dns_max_name_len: int = 50
    dns_entropy_min_label_len: int = 12      # shorter labels are too short for entropy to mean anything
    dns_entropy_threshold: float = 3.5       # Shannon bits per character

    # --- R-SPIKE-01 ---
    spike_multiplier: float = 3.0
    spike_min_minutes: int = 2               # consecutive minute buckets
    spike_min_baseline_ppm: float = 1.0      # floor so a near-silent baseline does not make everything a spike

    # --- R-PATTERN-DEV-01 ---
    pattern_proto_tvd: float = 0.30          # total-variation distance of protocol shares
    pattern_peer_novel_ratio: float = 0.50   # share of (src>dst) peers absent from the baseline
    pattern_rate_ratio: float = 3.0          # capture mean pkts/min vs baseline mean pkts/min

    # --- R-MULTI-IND-01 ---
    multi_indicator_min: int = 3
    p2_rule_ids: tuple[str, ...] = ("R-BEACON-01", "R-EXT-DEST-01", "R-PATTERN-DEV-01")

    # --- storage ---
    max_packet_refs: int = 500

    def snapshot(self) -> dict[str, Any]:
        """JSON-safe copy stored with every analysis run for reproducibility."""
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in asdict(self).items()}


CONFIG = PrioritizerConfig()