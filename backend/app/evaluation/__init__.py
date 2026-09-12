"""Scientific Evaluation Framework for SOC Platform."""

import statistics
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class MetricType(StrEnum):
    """Types of evaluation metrics."""

    DETECTION_RATE = "detection_rate"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    FALSE_NEGATIVE_RATE = "false_negative_rate"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    MEAN_TIME_TO_DETECT = "mttd"
    MEAN_TIME_TO_RESPOND = "mttr"
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    ACCURACY = "accuracy"


class EvaluationResult(BaseModel):
    """Result of an evaluation run."""

    result_id: str = Field(default_factory=lambda: f"eval_{uuid.uuid4().hex[:12]}")
    metric_type: MetricType
    value: float
    unit: str = ""
    timestamp: datetime = Field(default_factory=utc_now)
    sample_size: int = 0
    confidence_interval: tuple[float, float] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConfusionMatrix(BaseModel):
    """Confusion matrix for detection evaluation."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total if self.total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom > 0 else 0.0


class BenchmarkScenario(BaseModel):
    """Benchmark scenario for testing."""

    scenario_id: str = Field(default_factory=lambda: f"scn_{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    category: str = ""  # detection, performance, scalability
    events_count: int = 0
    expected_detections: int = 0
    expected_false_positives: int = 0
    timeout_seconds: int = 300
    metadata: dict[str, Any] = Field(default_factory=dict)


class BenchmarkRun(BaseModel):
    """Results of a benchmark run."""

    run_id: str = Field(default_factory=lambda: f"run_{uuid.uuid4().hex[:12]}")
    scenario_id: str
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    status: str = "pending"  # pending, running, completed, failed
    events_processed: int = 0
    detections_count: int = 0
    false_positives_count: int = 0
    processing_time_ms: float = 0.0
    throughput_eps: float = 0.0  # events per second
    avg_latency_ms: float = 0.0
    confusion_matrix: ConfusionMatrix = Field(default_factory=ConfusionMatrix)
    metrics: list[EvaluationResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class LatencyBucket(BaseModel):
    """Latency distribution bucket."""

    percentile: int
    value_ms: float


class PerformanceProfile(BaseModel):
    """Performance profile of the system."""

    profile_id: str = Field(default_factory=lambda: f"perf_{uuid.uuid4().hex[:8]}")
    created_at: datetime = Field(default_factory=utc_now)
    duration_seconds: int = 0
    total_events: int = 0
    events_per_second: float = 0.0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    error_rate: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_pct: float = 0.0


class EvaluationFramework:
    """Framework for scientific evaluation of SOC platform."""

    def __init__(self):
        self._benchmarks: dict[str, BenchmarkScenario] = {}
        self._runs: dict[str, BenchmarkRun] = {}
        self._results: list[EvaluationResult] = []
        self._latency_samples: list[float] = []

    def register_benchmark(self, scenario: BenchmarkScenario) -> None:
        """Register a benchmark scenario."""
        self._benchmarks[scenario.scenario_id] = scenario

    def create_benchmark_run(self, scenario_id: str) -> BenchmarkRun:
        """Create a new benchmark run."""
        if scenario_id not in self._benchmarks:
            raise ValueError(f"Scenario {scenario_id} not found")

        run = BenchmarkRun(scenario_id=scenario_id, status="pending")
        self._runs[run.run_id] = run
        return run

    def start_run(self, run_id: str) -> BenchmarkRun | None:
        """Start a benchmark run."""
        run = self._runs.get(run_id)
        if run:
            run.status = "running"
            run.started_at = utc_now()
        return run

    def record_detection(
        self,
        run_id: str,
        is_true_positive: bool,
        latency_ms: float = 0.0,
    ) -> None:
        """Record a detection result."""
        run = self._runs.get(run_id)
        if not run:
            return

        run.detections_count += 1
        if is_true_positive:
            run.confusion_matrix.true_positives += 1
        else:
            run.confusion_matrix.false_positives += 1
            run.false_positives_count += 1

        if latency_ms > 0:
            self._latency_samples.append(latency_ms)

    def record_event_processed(
        self,
        run_id: str,
        had_detection: bool = False,
        expected_detection: bool = False,
        latency_ms: float = 0.0,
    ) -> None:
        """Record an event processing result."""
        run = self._runs.get(run_id)
        if not run:
            return

        run.events_processed += 1

        # Update confusion matrix
        if expected_detection and had_detection:
            pass  # TP already counted in record_detection
        elif expected_detection and not had_detection:
            run.confusion_matrix.false_negatives += 1
        elif not expected_detection and had_detection:
            pass  # FP already counted in record_detection
        else:
            run.confusion_matrix.true_negatives += 1

        if latency_ms > 0:
            self._latency_samples.append(latency_ms)

    def complete_run(self, run_id: str) -> BenchmarkRun | None:
        """Complete a benchmark run and calculate metrics."""
        run = self._runs.get(run_id)
        if not run:
            return None

        run.completed_at = utc_now()
        run.status = "completed"

        # Calculate processing time
        delta = run.completed_at - run.started_at
        run.processing_time_ms = delta.total_seconds() * 1000

        # Calculate throughput
        if delta.total_seconds() > 0:
            run.throughput_eps = run.events_processed / delta.total_seconds()

        # Calculate latency stats
        if self._latency_samples:
            run.avg_latency_ms = statistics.mean(self._latency_samples)

        # Generate metrics
        cm = run.confusion_matrix
        run.metrics = [
            EvaluationResult(
                metric_type=MetricType.PRECISION,
                value=cm.precision,
                sample_size=cm.total,
            ),
            EvaluationResult(
                metric_type=MetricType.RECALL,
                value=cm.recall,
                sample_size=cm.total,
            ),
            EvaluationResult(
                metric_type=MetricType.F1_SCORE,
                value=cm.f1_score,
                sample_size=cm.total,
            ),
            EvaluationResult(
                metric_type=MetricType.ACCURACY,
                value=cm.accuracy,
                sample_size=cm.total,
            ),
            EvaluationResult(
                metric_type=MetricType.FALSE_POSITIVE_RATE,
                value=cm.false_positive_rate,
                sample_size=cm.total,
            ),
            EvaluationResult(
                metric_type=MetricType.THROUGHPUT,
                value=run.throughput_eps,
                unit="events/second",
                sample_size=run.events_processed,
            ),
            EvaluationResult(
                metric_type=MetricType.LATENCY,
                value=run.avg_latency_ms,
                unit="ms",
                sample_size=len(self._latency_samples),
            ),
        ]

        self._results.extend(run.metrics)
        self._latency_samples.clear()

        return run

    def calculate_performance_profile(
        self,
        latencies: list[float],
        duration_seconds: int,
        total_events: int,
        error_count: int = 0,
    ) -> PerformanceProfile:
        """Calculate performance profile from measurements."""
        profile = PerformanceProfile(
            duration_seconds=duration_seconds,
            total_events=total_events,
        )

        if duration_seconds > 0:
            profile.events_per_second = total_events / duration_seconds

        if latencies:
            sorted_latencies = sorted(latencies)
            profile.avg_latency_ms = statistics.mean(sorted_latencies)
            profile.p50_latency_ms = sorted_latencies[len(sorted_latencies) // 2]
            profile.p95_latency_ms = sorted_latencies[int(len(sorted_latencies) * 0.95)]
            profile.p99_latency_ms = sorted_latencies[int(len(sorted_latencies) * 0.99)]
            profile.max_latency_ms = sorted_latencies[-1]

        if total_events > 0:
            profile.error_rate = error_count / total_events

        return profile

    def evaluate_detection_engine(
        self,
        predictions: list[bool],
        ground_truth: list[bool],
    ) -> dict[str, float]:
        """Evaluate detection engine against ground truth."""
        if len(predictions) != len(ground_truth):
            raise ValueError("Predictions and ground truth must have same length")

        cm = ConfusionMatrix()
        for pred, truth in zip(predictions, ground_truth, strict=True):
            if truth and pred:
                cm.true_positives += 1
            elif truth and not pred:
                cm.false_negatives += 1
            elif not truth and pred:
                cm.false_positives += 1
            else:
                cm.true_negatives += 1

        return {
            "precision": cm.precision,
            "recall": cm.recall,
            "f1_score": cm.f1_score,
            "accuracy": cm.accuracy,
            "false_positive_rate": cm.false_positive_rate,
            "false_negative_rate": cm.false_negative_rate,
            "total_samples": cm.total,
        }

    def generate_evaluation_report(self) -> dict[str, Any]:
        """Generate comprehensive evaluation report."""
        completed_runs = [r for r in self._runs.values() if r.status == "completed"]

        if not completed_runs:
            return {"error": "No completed runs"}

        # Aggregate metrics
        all_precision = [r.confusion_matrix.precision for r in completed_runs]
        all_recall = [r.confusion_matrix.recall for r in completed_runs]
        all_f1 = [r.confusion_matrix.f1_score for r in completed_runs]
        all_throughput = [r.throughput_eps for r in completed_runs]

        return {
            "total_runs": len(completed_runs),
            "total_events_processed": sum(r.events_processed for r in completed_runs),
            "total_detections": sum(r.detections_count for r in completed_runs),
            "avg_precision": statistics.mean(all_precision) if all_precision else 0,
            "avg_recall": statistics.mean(all_recall) if all_recall else 0,
            "avg_f1_score": statistics.mean(all_f1) if all_f1 else 0,
            "avg_throughput_eps": statistics.mean(all_throughput) if all_throughput else 0,
            "runs": [
                {
                    "run_id": r.run_id,
                    "scenario_id": r.scenario_id,
                    "precision": r.confusion_matrix.precision,
                    "recall": r.confusion_matrix.recall,
                    "f1_score": r.confusion_matrix.f1_score,
                    "throughput_eps": r.throughput_eps,
                }
                for r in completed_runs
            ],
        }

    def get_benchmark(self, scenario_id: str) -> BenchmarkScenario | None:
        """Get benchmark scenario by ID."""
        return self._benchmarks.get(scenario_id)

    def get_run(self, run_id: str) -> BenchmarkRun | None:
        """Get benchmark run by ID."""
        return self._runs.get(run_id)

    def list_benchmarks(self) -> list[BenchmarkScenario]:
        """List all benchmark scenarios."""
        return list(self._benchmarks.values())

    def list_runs(self, scenario_id: str | None = None) -> list[BenchmarkRun]:
        """List benchmark runs."""
        runs = list(self._runs.values())
        if scenario_id:
            runs = [r for r in runs if r.scenario_id == scenario_id]
        return sorted(runs, key=lambda r: r.started_at, reverse=True)

    def get_metrics(self) -> dict[str, Any]:
        """Get framework metrics."""
        return {
            "total_benchmarks": len(self._benchmarks),
            "total_runs": len(self._runs),
            "completed_runs": len([r for r in self._runs.values() if r.status == "completed"]),
            "total_results": len(self._results),
        }


# Default benchmark scenarios
DEFAULT_BENCHMARKS = [
    BenchmarkScenario(
        scenario_id="phishing_detection",
        name="Phishing Email Detection",
        description="Evaluate phishing email detection accuracy",
        category="detection",
        events_count=1000,
        expected_detections=100,
        expected_false_positives=10,
    ),
    BenchmarkScenario(
        scenario_id="brute_force_detection",
        name="Brute Force Attack Detection",
        description="Evaluate brute force attack detection",
        category="detection",
        events_count=5000,
        expected_detections=50,
        expected_false_positives=5,
    ),
    BenchmarkScenario(
        scenario_id="high_throughput",
        name="High Throughput Processing",
        description="Evaluate event processing at high volume",
        category="performance",
        events_count=100000,
        timeout_seconds=60,
    ),
    BenchmarkScenario(
        scenario_id="latency_test",
        name="Latency Under Load",
        description="Measure detection latency under sustained load",
        category="performance",
        events_count=10000,
        timeout_seconds=120,
    ),
]


# Singleton
_framework: EvaluationFramework | None = None


def get_evaluation_framework() -> EvaluationFramework:
    """Get evaluation framework singleton."""
    global _framework
    if _framework is None:
        _framework = EvaluationFramework()
        # Register default benchmarks
        for benchmark in DEFAULT_BENCHMARKS:
            _framework.register_benchmark(benchmark)
    return _framework
