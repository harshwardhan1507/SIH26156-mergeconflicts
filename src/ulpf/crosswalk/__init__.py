"""
ULPF Crosswalk Layer.

Provides clean bidirectional translation from Universal Event Schema (UES v1.2.0)
into Open Cybersecurity Schema Framework (OCSF v1.1.0) and Elastic Common Schema (ECS v8.x).
"""
from ulpf.crosswalk.ecs import to_ecs
from ulpf.crosswalk.ocsf import to_ocsf

__all__ = ["to_ecs", "to_ocsf"]
