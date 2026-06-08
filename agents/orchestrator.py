"""
Agent Orchestrator

Graph-based orchestration of the AI agent ensemble.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, TypedDict
from uuid import UUID

try:
    # pyrefly: ignore [missing-import]
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - fallback for incomplete local installs
    END = "__end__"
    StateGraph = None

from agents.base import OllamaClient
from agents.behavioral_agent import BehavioralInterpretationAgent
from agents.cache import AnalysisCache, get_analysis_cache
from agents.intent_agent import ThreatIntentAgent
from agents.mitre_agent import MitreReasoningAgent
from agents.triage_agent import TriageNarrativeAgent
from agents.merge_agent import MergeNarrativeAgent
from core.config import get_settings
from core.logging import get_logger
from shared_models.agents import AgentError as AgentErrorModel
from shared_models.agents import AgentOutput
from shared_models.chunks import ChunkSummary

logger = get_logger(__name__)

PROMPT_SCHEMA_VERSION = "agent_graph_v2"


class AgentGraphState(TypedDict, total=False):
    """Shared state passed through the multi-agent graph."""

    chunk_id: UUID
    summary_dict: dict[str, Any]
    output: AgentOutput
    errors: list[AgentErrorModel]
    total_time_ms: int
    skip_if_not_suspicious: bool
    stop_downstream: bool
    stop_reason: str


class AgentOrchestrator:
    """
    Orchestrates the AI agent ensemble for threat analysis.

    Graph:
    Behavioral Interpretation -> Threat Intent -> MITRE Mapping -> Triage

    Downstream agents receive the original chunk summary plus prior agent
    outputs through an explicit graph context.
    """

    def __init__(self, client: OllamaClient | None = None, use_cache: bool = True):
        self.settings = get_settings()
        self.client = client or OllamaClient()
        self.use_cache = use_cache
        self.cache: AnalysisCache = get_analysis_cache()

        self.behavioral_agent = BehavioralInterpretationAgent(self.client)
        self.intent_agent = ThreatIntentAgent(self.client)
        self.mitre_agent = MitreReasoningAgent(self.client)
        self.triage_agent = TriageNarrativeAgent(self.client)
        self.merge_agent = MergeNarrativeAgent(self.client)

        self.analyses_completed = 0
        self.cache_hits = 0
        self.errors: list[AgentErrorModel] = []
        self._graph = self._build_graph()

    def _build_graph(self) -> Any:
        """Build the LangGraph state machine when the dependency is available."""
        if StateGraph is None:
            logger.warning("LangGraph unavailable; using internal graph runner fallback")
            return None

        graph = StateGraph(AgentGraphState)
        graph.add_node("behavioral", self._behavioral_node)
        graph.add_node("intent", self._intent_node)
        graph.add_node("mitre", self._mitre_node)
        graph.add_node("triage", self._triage_node)
        graph.add_node("finalize", self._finalize_node)

        graph.set_entry_point("behavioral")
        graph.add_conditional_edges(
            "behavioral",
            self._route_after_behavioral,
            {"intent": "intent", "finalize": "finalize"},
        )
        graph.add_edge("intent", "mitre")
        graph.add_edge("mitre", "triage")
        graph.add_edge("triage", "finalize")
        graph.add_edge("finalize", END)
        return graph.compile()

    async def analyze(
        self,
        summary: ChunkSummary,
        skip_if_not_suspicious: bool = True,
    ) -> AgentOutput:
        """
        Run graph-based agent analysis on a chunk summary.
        """
        chunk_id = summary.chunk_id
        summary_dict = summary.model_dump(mode="json")
        cache_payload = {
            "prompt_schema_version": PROMPT_SCHEMA_VERSION,
            "summary": summary_dict,
        }

        if self.use_cache:
            chunk_hash = self.cache.compute_chunk_hash(cache_payload)
            cached_result = self.cache.get_cached_result(
                chunk_hash,
                model=self.client.model,
                temperature=self.client.temperature,
            )
            if cached_result:
                self.cache_hits += 1
                self.analyses_completed += 1
                logger.info(
                    f"Returning cached graph analysis | chunk_id={chunk_id}, "
                    f"chunk_hash={chunk_hash[:16]}"
                )
                self._retarget_output_chunk_id(cached_result, chunk_id)
                return cached_result

        logger.info(f"Starting graph agent analysis | chunk_id={chunk_id}")

        flagged_rules = summary.flagged_rules or []

        if len(flagged_rules) <= 1:
            initial_state: AgentGraphState = {
                "chunk_id": chunk_id,
                "summary_dict": summary_dict,
                "output": AgentOutput(chunk_id=chunk_id),
                "errors": [],
                "total_time_ms": 0,
                "skip_if_not_suspicious": skip_if_not_suspicious,
                "stop_downstream": False,
            }
            final_state = await self._run_graph(initial_state)
            output = final_state["output"]
        else:
            logger.info(f"Fanning out graph execution for {len(flagged_rules)} rules | chunk_id={chunk_id}")
            
            async def _run_for_rule(rule_dict: dict) -> AgentOutput:
                sub_summary = summary.model_copy(update={"flagged_rules": [rule_dict]})
                state: AgentGraphState = {
                    "chunk_id": chunk_id,
                    "summary_dict": sub_summary.model_dump(mode="json"),
                    "output": AgentOutput(chunk_id=chunk_id),
                    "errors": [],
                    "total_time_ms": 0,
                    "skip_if_not_suspicious": skip_if_not_suspicious,
                    "stop_downstream": False,
                }
                final_state = await self._run_graph(state)
                return final_state["output"]

            tasks = [_run_for_rule(r) for r in flagged_rules]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            valid_outputs = [r for r in results if isinstance(r, AgentOutput) and r.has_agent_result()]
            
            all_errors = []
            for r in results:
                if isinstance(r, Exception):
                    all_errors.append(AgentErrorModel(
                        chunk_id=chunk_id,
                        agent_name="orchestrator",
                        error_type="map_reduce_error",
                        error_message=str(r),
                        timestamp=datetime.utcnow()
                    ))
                elif isinstance(r, AgentOutput):
                    all_errors.extend(r.errors)

            if not valid_outputs:
                output = AgentOutput(chunk_id=chunk_id)
                output.errors = all_errors
            elif len(valid_outputs) == 1:
                output = valid_outputs[0]
                output.errors.extend(all_errors)
            else:
                # Merge multiple successful outputs
                triage_results = [o.triage.model_dump(mode="json") for o in valid_outputs if o.triage]
                output = AgentOutput(chunk_id=chunk_id)
                output.errors = all_errors
                output.total_processing_time_ms = max((o.total_processing_time_ms for o in valid_outputs), default=0)
                
                # Pick the best supporting agent results based on behavioral is_suspicious and overall confidence
                # (triage no longer has suspicious field - that's in behavioral agent)
                best_sub = max(valid_outputs, key=lambda o: (
                    1 if (o.behavioral and o.behavioral.is_suspicious) else 0,
                    o.overall_confidence
                ))
                output.behavioral = best_sub.behavioral
                output.intent = best_sub.intent
                output.mitre = best_sub.mitre

                if triage_results:
                    try:
                        merge_summary = {"_triage_results_to_merge": triage_results}
                        merged_triage = await self.merge_agent.analyze(merge_summary, chunk_id)
                        output.triage = merged_triage
                        output.total_processing_time_ms += merged_triage.processing_time_ms
                    except Exception as e:
                        all_errors.append(AgentErrorModel(
                            chunk_id=chunk_id,
                            agent_name="merge_agent",
                            error_type="merge_error",
                            error_message=str(e),
                            timestamp=datetime.utcnow()
                        ))
                        output.triage = best_sub.triage
                else:
                    output.triage = best_sub.triage

                output.compute_overall_confidence()
                # Let AI decide if human review is needed (from triage agent)
                if output.triage and output.triage.ai_needs_human_review is not None:
                    output.requires_human_review = output.triage.ai_needs_human_review
                else:
                    # Fallback to old logic if AI didn't provide a decision
                    output.requires_human_review = self._needs_human_review(output)

        if output.has_agent_result():
            self.analyses_completed += 1
            if self.use_cache:
                chunk_hash = self.cache.compute_chunk_hash(cache_payload)
                self.cache.cache_result(
                    chunk_hash,
                    output,
                    model=self.client.model,
                    temperature=self.client.temperature,
                )
        else:
            logger.warning(
                f"Graph analysis produced no valid agent outputs | chunk_id={chunk_id}, "
                f"errors={len(output.errors)}"
            )

        logger.info(
            f"Graph agent analysis complete | chunk_id={chunk_id}, "
            f"has_result={output.has_agent_result()}, "
            f"overall_confidence={output.overall_confidence}, "
            f"errors={len(output.errors)}, "
            f"requires_review={output.requires_human_review}, "
            f"time_ms={output.total_processing_time_ms}"
        )
        return output

    async def _run_graph(self, state: AgentGraphState) -> AgentGraphState:
        """Run the compiled LangGraph, or an equivalent internal fallback."""
        if self._graph is not None:
            return await self._graph.ainvoke(state)

        state = await self._behavioral_node(state)
        if self._route_after_behavioral(state) == "finalize":
            return await self._finalize_node(state)
        state = await self._intent_node(state)
        state = await self._mitre_node(state)
        state = await self._triage_node(state)
        return await self._finalize_node(state)

    async def _behavioral_node(self, state: AgentGraphState) -> AgentGraphState:
        chunk_id = state["chunk_id"]
        output = state["output"]
        try:
            behavioral = await self.behavioral_agent.analyze(state["summary_dict"], chunk_id)
            output.behavioral = behavioral
            state["total_time_ms"] = state.get("total_time_ms", 0) + behavioral.processing_time_ms
            if (
                state.get("skip_if_not_suspicious", True)
                and not behavioral.is_suspicious
            ):
                state["stop_downstream"] = True
                state["stop_reason"] = "behavioral_benign"
        except Exception as e:
            self._record_agent_error(state, "behavioral_interpretation", str(e))
            # Behavioral agent failed. Without it, we cannot determine if the chunk is suspicious, so we must stop.
            state["stop_downstream"] = True
            state["stop_reason"] = "behavioral_failed"
        return state

    def _route_after_behavioral(self, state: AgentGraphState) -> str:
        return "finalize" if state.get("stop_downstream") else "intent"

    async def _intent_node(self, state: AgentGraphState) -> AgentGraphState:
        chunk_id = state["chunk_id"]
        output = state["output"]
        try:
            intent = await self.intent_agent.analyze(
                self._summary_with_context(state, include=("behavioral",)),
                chunk_id,
            )
            output.intent = intent
            state["total_time_ms"] = state.get("total_time_ms", 0) + intent.processing_time_ms
        except Exception as e:
            self._record_agent_error(state, "threat_intent", str(e))
        return state

    async def _mitre_node(self, state: AgentGraphState) -> AgentGraphState:
        chunk_id = state["chunk_id"]
        output = state["output"]
        try:
            mitre = await self.mitre_agent.analyze(
                self._summary_with_context(state, include=("behavioral", "intent")),
                chunk_id,
            )
            output.mitre = mitre
            state["total_time_ms"] = state.get("total_time_ms", 0) + mitre.processing_time_ms
        except Exception as e:
            self._record_agent_error(state, "mitre_mapping", str(e))
        return state

    async def _triage_node(self, state: AgentGraphState) -> AgentGraphState:
        chunk_id = state["chunk_id"]
        output = state["output"]
        try:
            triage = await self.triage_agent.analyze(
                self._summary_with_context(
                    state,
                    include=("behavioral", "intent", "mitre"),
                    include_errors=True,
                ),
                chunk_id,
            )
            output.triage = triage
            state["total_time_ms"] = state.get("total_time_ms", 0) + triage.processing_time_ms
        except Exception as e:
            self._record_agent_error(state, "triage", str(e))
        return state

    async def _finalize_node(self, state: AgentGraphState) -> AgentGraphState:
        output = state["output"]
        output.total_processing_time_ms = state.get("total_time_ms", 0)
        output.errors = list(state.get("errors", []))
        output.compute_overall_confidence()

        if state.get("stop_reason") == "behavioral_benign":
            output.requires_human_review = False
        elif output.has_agent_result():
            # Let AI decide if human review is needed (from triage agent)
            if output.triage and output.triage.ai_needs_human_review is not None:
                output.requires_human_review = output.triage.ai_needs_human_review
            else:
                # Fallback to old logic if AI didn't provide a decision
                output.requires_human_review = self._needs_human_review(output)
        else:
            output.requires_human_review = True
        return state

    def _summary_with_context(
        self,
        state: AgentGraphState,
        include: tuple[str, ...],
        include_errors: bool = False,
    ) -> dict[str, Any]:
        summary = dict(state["summary_dict"])
        output = state["output"]
        prior_outputs: dict[str, Any] = {}
        for name in include:
            result = getattr(output, name, None)
            if result:
                prior_outputs[name] = result.model_dump(mode="json", exclude_none=True)
        summary["_agent_context"] = {
            "prompt_schema_version": PROMPT_SCHEMA_VERSION,
            "prior_outputs": prior_outputs,
            "agent_errors": [
                error.model_dump(mode="json")
                for error in state.get("errors", [])
            ] if include_errors else [],
        }
        return summary

    def _record_agent_error(
        self,
        state: AgentGraphState,
        agent_name: str,
        error_message: str,
    ) -> None:
        error = AgentErrorModel(
            chunk_id=state["chunk_id"],
            agent_name=agent_name,
            error_type="analysis_error",
            error_message=error_message,
            timestamp=datetime.utcnow(),
        )
        state.setdefault("errors", []).append(error)
        self.errors.append(error)
        logger.error(
            f"Agent error | agent={agent_name}, chunk_id={state['chunk_id']}, "
            f"error={error_message}"
        )

    async def analyze_batch(
        self,
        summaries: list[ChunkSummary],
        max_concurrent: int = 3,
        skip_if_not_suspicious: bool = False,
    ) -> list[AgentOutput]:
        """
        Analyze multiple summaries with controlled concurrency.

        The returned list includes one AgentOutput per input summary, preserving
        chunk identity even when a chunk fails. Callers should use chunk_id
        rather than positional zip for downstream joins.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_semaphore(summary: ChunkSummary) -> AgentOutput:
            async with semaphore:
                try:
                    return await self.analyze(summary, skip_if_not_suspicious=skip_if_not_suspicious)
                except Exception as e:
                    logger.error(
                        f"Batch analysis error | chunk_id={summary.chunk_id}, error={e}"
                    )
                    output = AgentOutput(chunk_id=summary.chunk_id)
                    output.errors.append(
                        AgentErrorModel(
                            chunk_id=summary.chunk_id,
                            agent_name="orchestrator",
                            error_type="batch_analysis_error",
                            error_message=str(e),
                            timestamp=datetime.utcnow(),
                        )
                    )
                    return output

        tasks = [analyze_with_semaphore(s) for s in summaries]
        return await asyncio.gather(*tasks)

    def _needs_human_review(self, output: AgentOutput) -> bool:
        """Determine if output needs human review."""
        if output.behavioral and output.behavioral.is_suspicious:
            return True

        if output.triage:
            from shared_models.agents import IncidentPriority

            high_priorities = {
                IncidentPriority.CRITICAL,
                IncidentPriority.HIGH,
                IncidentPriority.MEDIUM,
            }
            if output.triage.priority in high_priorities:
                return True

        if output.overall_confidence < self.settings.min_confidence_threshold:
            return True

        return False

    def _retarget_output_chunk_id(self, output: AgentOutput, chunk_id: UUID) -> None:
        """Update cached output IDs to match the current chunk."""
        output.chunk_id = chunk_id
        for result in (output.behavioral, output.intent, output.mitre, output.triage):
            if result:
                result.chunk_id = chunk_id
        for error in output.errors:
            error.chunk_id = chunk_id

    async def health_check(self) -> dict[str, Any]:
        """Check agent system health."""
        ollama_ok = await self.client.health_check()

        return {
            "ollama_available": ollama_ok,
            "model": self.client.model,
            "analyses_completed": self.analyses_completed,
            "error_count": len(self.errors),
            "graph_enabled": self._graph is not None,
        }

    def get_stats(self) -> dict[str, Any]:
        """Get orchestrator statistics including cache metrics."""
        return {
            "analyses_completed": self.analyses_completed,
            "cache_hits": self.cache_hits,
            "cache_enabled": self.use_cache,
            "error_count": len(self.errors),
            "graph_enabled": self._graph is not None,
            "prompt_schema_version": PROMPT_SCHEMA_VERSION,
            "cache": self.cache.get_stats() if self.use_cache else None,
            "agents": {
                "behavioral": self.behavioral_agent.get_stats(),
                "intent": self.intent_agent.get_stats(),
                "mitre": self.mitre_agent.get_stats(),
                "triage": self.triage_agent.get_stats(),
            },
            "model": self.client.model,
            "temperature": self.client.temperature,
        }

    async def close(self):
        """Close resources."""
        await self.client.close()
