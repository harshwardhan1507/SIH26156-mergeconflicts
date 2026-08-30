"""
ULPF Crosswalk Layer.

Provides clean bidirectional translation from Universal Event Schema (UES v1.2.0)
into Open Cybersecurity Schema Framework (OCSF v1.1.0) and Elastic Common Schema (ECS v8.x).
"""
from ulpf.crosswalk.ocsf import to_ocsf
from ulpf.crosswalk.ecs import to_ecs

__all__ = ["to_ocsf", "to_ecs"]
