"""Predictive attack path: project the attacker's likely next moves."""
from __future__ import annotations

from app.engines.prediction.engine import PredictionEngine, build_prediction_engine

__all__ = ["PredictionEngine", "build_prediction_engine"]
