"""Sigma rule compiler and matching engine for Layer 1 deterministic detection.

Implements a lightweight Sigma rule parser that compiles YAML rules into
efficient detection logic. Supports common Sigma modifiers and conditions.

Reference: https://github.com/SigmaHQ/sigma-specification
"""

import re
from pathlib import Path
from typing import Any

import yaml

from backend.app.core.logging import get_logger
from backend.app.detection.exceptions import RuleCompilationError, RuleLoadError
from backend.app.detection.interfaces import DetectionLayer, DetectionRule, RuleEngine, RuleType
from backend.app.detection.models import DetectionMatch, MatchConfidence
from backend.app.detection.rules.base import (
    compile_regex_safe,
    get_searchable_fields,
    safe_str,
    severity_from_string,
)
from backend.app.schemas.events import EventSeverity, SecurityEvent

logger = get_logger("cyber_ai.detection.sigma")


class SigmaModifier:
    """Sigma field modifier implementations."""

    @staticmethod
    def contains(field_value: str, pattern: str) -> bool:
        """Check if field contains pattern (case-insensitive)."""
        return pattern.lower() in field_value.lower()

    @staticmethod
    def startswith(field_value: str, pattern: str) -> bool:
        """Check if field starts with pattern (case-insensitive)."""
        return field_value.lower().startswith(pattern.lower())

    @staticmethod
    def endswith(field_value: str, pattern: str) -> bool:
        """Check if field ends with pattern (case-insensitive)."""
        return field_value.lower().endswith(pattern.lower())

    @staticmethod
    def regex(field_value: str, pattern: str) -> bool:
        """Check if field matches regex pattern."""
        compiled = compile_regex_safe(pattern)
        if compiled is None:
            return False
        return bool(compiled.search(field_value))

    @staticmethod
    def equals(field_value: str, pattern: str) -> bool:
        """Check exact match (case-insensitive)."""
        return field_value.lower() == pattern.lower()

    @staticmethod
    def equals_exact(field_value: str, pattern: str) -> bool:
        """Check exact match (case-sensitive)."""
        return field_value == pattern


class CompiledCondition:
    """Compiled detection condition from Sigma rule."""

    def __init__(
        self,
        field: str,
        patterns: list[str],
        modifier: str = "contains",
        negate: bool = False,
        match_all: bool = False,
    ) -> None:
        self.field = field
        self.patterns = patterns
        self.modifier = modifier
        self.negate = negate
        self.match_all = match_all  # all vs any pattern matching

        # Precompile regex patterns
        self._compiled_regex: list[re.Pattern[str]] = []
        if modifier == "re":
            for p in patterns:
                compiled = compile_regex_safe(p)
                if compiled:
                    self._compiled_regex.append(compiled)

    def evaluate(self, fields: dict[str, Any]) -> tuple[bool, str | None]:  # noqa: C901
        """Evaluate condition against event fields.

        Returns:
            Tuple of (matched: bool, matched_value: str | None)
        """
        # Get field value
        field_value = fields.get(self.field)
        if field_value is None:
            # Try case-insensitive field lookup
            field_lower = self.field.lower()
            for key, value in fields.items():
                if key.lower() == field_lower:
                    field_value = value
                    break

        if field_value is None:
            return (self.negate, None)  # Field not present

        value_str = safe_str(field_value)
        matched_pattern: str | None = None

        # Evaluate based on modifier
        if self.modifier == "re":
            matches = []
            for i, compiled in enumerate(self._compiled_regex):
                if compiled.search(value_str):
                    matches.append(self.patterns[i])
            if self.match_all:
                result = len(matches) == len(self.patterns)
            else:
                result = len(matches) > 0
            if matches:
                matched_pattern = matches[0]
        else:
            # Get the appropriate check function
            check_fn = getattr(SigmaModifier, self.modifier, SigmaModifier.contains)
            matches = []
            for pattern in self.patterns:
                if check_fn(value_str, pattern):
                    matches.append(pattern)

            if self.match_all:
                result = len(matches) == len(self.patterns)
            else:
                result = len(matches) > 0
            if matches:
                matched_pattern = matches[0]

        if self.negate:
            result = not result

        return (result, matched_pattern if result else None)


class SigmaRule(DetectionRule):
    """Compiled Sigma detection rule."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: EventSeverity,
        conditions: list[CompiledCondition],
        condition_logic: str = "all",  # all, any, or expression
        description: str = "",
        mitre_techniques: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        references: list[str] | None = None,
        tags: list[str] | None = None,
        enabled: bool = True,
        version: str = "1.0.0",
        logsource: dict[str, str] | None = None,
    ) -> None:
        self._rule_id = rule_id
        self._rule_name = rule_name
        self._severity = severity
        self._conditions = conditions
        self._condition_logic = condition_logic
        self._description = description
        self._mitre_techniques = mitre_techniques or []
        self._mitre_tactics = mitre_tactics or []
        self._references = references or []
        self._tags = tags or []
        self._enabled = enabled
        self._version = version
        self._logsource = logsource or {}

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def rule_name(self) -> str:
        return self._rule_name

    @property
    def rule_type(self) -> RuleType:
        return RuleType.SIGMA

    @property
    def severity(self) -> EventSeverity:
        return self._severity

    @property
    def description(self) -> str:
        return self._description

    @property
    def mitre_techniques(self) -> list[str]:
        return self._mitre_techniques

    @property
    def mitre_tactics(self) -> list[str]:
        return self._mitre_tactics

    @property
    def references(self) -> list[str]:
        return self._references

    @property
    def tags(self) -> list[str]:
        return self._tags

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def version(self) -> str:
        return self._version

    def _check_logsource(self, event: SecurityEvent) -> bool:
        """Check if event matches rule's logsource filter."""
        if not self._logsource:
            return True

        # Check product/service/category against event source_type
        product = self._logsource.get("product", "").lower()
        service = self._logsource.get("service", "").lower()
        category = self._logsource.get("category", "").lower()

        event_source = event.source.lower()
        event_source_type = event.source_type.lower()
        event_type = event.event_type.lower()

        # Flexible matching
        if product and product not in event_source and product not in event_source_type:
            return False
        if service and service not in event_source and service not in event_type:
            return False
        if category and category not in event_source_type and category not in event_type:
            return False

        return True

    def matches(self, event: SecurityEvent) -> DetectionMatch | None:
        """Evaluate rule against SecurityEvent."""
        if not self._enabled:
            return None

        # Check logsource filter first
        if not self._check_logsource(event):
            return None

        # Extract searchable fields
        fields = get_searchable_fields(event)

        # Evaluate conditions
        matched_conditions: list[tuple[str, str]] = []
        for condition in self._conditions:
            matched, matched_value = condition.evaluate(fields)
            if matched and matched_value:
                matched_conditions.append((condition.field, matched_value))

        # Apply condition logic
        if self._condition_logic == "all":
            triggered = len(matched_conditions) == len(self._conditions)
        elif self._condition_logic == "any":
            triggered = len(matched_conditions) > 0
        else:
            # For now, treat expressions as "any"
            triggered = len(matched_conditions) > 0

        if not triggered or not matched_conditions:
            return None

        # Build match result
        matched_field, matched_value = matched_conditions[0]
        match_details: dict[str, Any] = {
            "conditions_matched": len(matched_conditions),
            "total_conditions": len(self._conditions),
            "condition_logic": self._condition_logic,
            "all_matches": matched_conditions,
            "logsource": self._logsource,
        }

        return DetectionMatch(
            rule_id=self._rule_id,
            rule_name=self._rule_name,
            rule_type=RuleType.SIGMA,
            rule_version=self._version,
            detection_layer=DetectionLayer.L1_DETERMINISTIC,
            severity=self._severity,
            confidence=MatchConfidence.HIGH,
            matched_field=matched_field,
            matched_value=str(matched_value),
            match_details=match_details,
            mitre_techniques=self._mitre_techniques,
            mitre_tactics=self._mitre_tactics,
            description=self._description,
            references=self._references,
            tags=self._tags,
        )


class SigmaEngine(RuleEngine):
    """Sigma rule compilation and evaluation engine."""

    def __init__(self) -> None:
        self._rules: dict[str, SigmaRule] = {}

    @property
    def engine_name(self) -> str:
        return "sigma_engine"

    @property
    def rule_type(self) -> RuleType:
        return RuleType.SIGMA

    @property
    def detection_layer(self) -> DetectionLayer:
        return DetectionLayer.L1_DETERMINISTIC

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def load_rules(self, rules_path: str | None = None) -> int:
        """Load Sigma rules from YAML files in directory."""
        if rules_path is None:
            # Load bundled rules
            bundled_path = Path(__file__).parent / "sigma_rules"
            if bundled_path.exists():
                rules_path = str(bundled_path)
            else:
                logger.warning("No Sigma rules path provided and no bundled rules found")
                return 0

        path = Path(rules_path)
        if not path.exists():
            logger.warning("Sigma rules path does not exist: %s", rules_path)
            return 0

        loaded = 0
        yaml_files: list[Path] = []

        if path.is_file() and path.suffix in (".yml", ".yaml"):
            yaml_files = [path]
        elif path.is_dir():
            yaml_files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))

        for yaml_file in yaml_files:
            try:
                rule = self._load_rule_file(yaml_file)
                if rule:
                    self._rules[rule.rule_id] = rule
                    loaded += 1
            except Exception as e:
                logger.warning("Failed to load Sigma rule %s: %s", yaml_file, e)

        logger.info("Loaded %d Sigma rules from %s", loaded, rules_path)
        return loaded

    def _load_rule_file(self, file_path: Path) -> SigmaRule | None:
        """Load and compile a single Sigma YAML rule file."""
        try:
            with open(file_path, encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RuleLoadError(f"Invalid YAML: {e}", rule_path=str(file_path)) from e

        if not isinstance(rule_data, dict):
            return None

        return self._compile_rule(rule_data, str(file_path))

    def _compile_rule(self, rule_data: dict[str, Any], source: str = "inline") -> SigmaRule:
        """Compile a Sigma rule dictionary into a SigmaRule object."""
        # Extract metadata
        rule_id = rule_data.get("id", f"sigma_{hash(str(rule_data)) & 0xFFFFFFFF:08x}")
        rule_name = rule_data.get("title", "Unnamed Sigma Rule")
        description = rule_data.get("description", "")
        status = rule_data.get("status", "experimental")

        # Severity mapping
        level = rule_data.get("level", "medium")
        severity = severity_from_string(level)

        # MITRE ATT&CK tags
        tags = rule_data.get("tags", [])
        mitre_techniques: list[str] = []
        mitre_tactics: list[str] = []
        for tag in tags:
            if isinstance(tag, str):
                if tag.startswith("attack.t"):
                    mitre_techniques.append(tag.replace("attack.", "").upper())
                elif tag.startswith("attack."):
                    mitre_tactics.append(tag.replace("attack.", ""))

        # References
        references = rule_data.get("references", [])
        if not isinstance(references, list):
            references = []

        # Logsource
        logsource = rule_data.get("logsource", {})
        if not isinstance(logsource, dict):
            logsource = {}

        # Compile detection conditions
        detection = rule_data.get("detection", {})
        if not isinstance(detection, dict):
            raise RuleCompilationError(
                "Missing or invalid 'detection' block",
                rule_id=rule_id,
                rule_type="sigma",
            )

        conditions = self._compile_detection(detection)
        condition_logic = self._parse_condition_logic(detection.get("condition", "all of them"))

        # Enabled based on status
        enabled = status not in ("deprecated", "unsupported")

        return SigmaRule(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            conditions=conditions,
            condition_logic=condition_logic,
            description=description,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            references=references,
            tags=tags,
            enabled=enabled,
            logsource=logsource,
        )

    def _compile_detection(self, detection: dict[str, Any]) -> list[CompiledCondition]:
        """Compile Sigma detection block into conditions."""
        conditions: list[CompiledCondition] = []

        for key, value in detection.items():
            if key == "condition":
                continue  # Skip the condition expression

            if isinstance(value, dict):
                # Field conditions dict
                conditions.extend(self._compile_selection(value))
            elif isinstance(value, list):
                # List of patterns for a field
                conditions.append(
                    CompiledCondition(
                        field=key,
                        patterns=[str(v) for v in value],
                        modifier="contains",
                    )
                )

        return conditions

    def _compile_selection(self, selection: dict[str, Any]) -> list[CompiledCondition]:
        """Compile a selection block into conditions."""
        conditions: list[CompiledCondition] = []

        for field_spec, patterns in selection.items():
            # Parse field and modifier
            field, modifier, negate, match_all = self._parse_field_spec(field_spec)

            # Normalize patterns to list
            if not isinstance(patterns, list):
                patterns = [patterns]

            pattern_strs = [str(p) for p in patterns if p is not None]
            if not pattern_strs:
                continue

            conditions.append(
                CompiledCondition(
                    field=field,
                    patterns=pattern_strs,
                    modifier=modifier,
                    negate=negate,
                    match_all=match_all,
                )
            )

        return conditions

    def _parse_field_spec(self, field_spec: str) -> tuple[str, str, bool, bool]:
        """Parse Sigma field specification with modifiers.

        Args:
            field_spec: Field name with optional modifiers (e.g., "CommandLine|contains|all")

        Returns:
            Tuple of (field_name, modifier, negate, match_all)
        """
        parts = field_spec.split("|")
        field = parts[0]
        modifier = "contains"  # Default
        negate = False
        match_all = False

        for part in parts[1:]:
            part_lower = part.lower()
            if part_lower == "contains":
                modifier = "contains"
            elif part_lower == "startswith":
                modifier = "startswith"
            elif part_lower == "endswith":
                modifier = "endswith"
            elif part_lower == "re":
                modifier = "regex"
            elif part_lower == "base64":
                modifier = "contains"  # TODO: Implement base64 decode
            elif part_lower == "all":
                match_all = True
            elif part_lower == "not":
                negate = True

        return field, modifier, negate, match_all

    def _parse_condition_logic(self, condition: str) -> str:
        """Parse Sigma condition expression into logic type."""
        condition_lower = condition.lower().strip()

        if condition_lower in ("all of them", "all"):
            return "all"
        if condition_lower in ("1 of them", "any of them", "any"):
            return "any"
        if " and " in condition_lower and " or " not in condition_lower:
            return "all"
        if " or " in condition_lower and " and " not in condition_lower:
            return "any"

        # Complex expressions default to "any" for now
        return "any"

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a compiled rule to the engine."""
        if isinstance(rule, SigmaRule):
            self._rules[rule.rule_id] = rule
        else:
            logger.warning("Attempted to add non-Sigma rule to SigmaEngine: %s", type(rule))

    def add_rule_from_dict(self, rule_data: dict[str, Any]) -> SigmaRule:
        """Compile and add a rule from dictionary."""
        rule = self._compile_rule(rule_data)
        self._rules[rule.rule_id] = rule
        return rule

    def add_rule_from_yaml(self, yaml_str: str) -> SigmaRule:
        """Compile and add a rule from YAML string."""
        rule_data = yaml.safe_load(yaml_str)
        return self.add_rule_from_dict(rule_data)

    def evaluate(self, event: SecurityEvent) -> list[DetectionMatch]:
        """Evaluate all rules against an event."""
        matches: list[DetectionMatch] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                match = rule.matches(event)
                if match:
                    matches.append(match)
            except Exception as e:
                logger.warning("Error evaluating Sigma rule %s: %s", rule.rule_id, e)

        return matches

    def get_rule(self, rule_id: str) -> SigmaRule | None:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[DetectionRule]:
        """List all loaded rules."""
        return list(self._rules.values())

    def clear_rules(self) -> None:
        """Remove all loaded rules."""
        self._rules.clear()
