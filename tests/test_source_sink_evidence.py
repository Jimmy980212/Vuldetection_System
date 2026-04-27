import json
from pathlib import Path

from agents.InferenceAgent import InferenceAgent
from agents.preprocess_components import ProgramSliceBuilder


ROOT = Path(__file__).resolve().parents[1]


def test_program_slice_contains_source_sink_evidence_package(monkeypatch):
    monkeypatch.setenv("VULDET_MAX_PROMPT_TOKENS", "3000")
    builder = ProgramSliceBuilder()
    target = ROOT / "data" / "test_codes" / "joern_phase2_high_risk.c"

    program_slice = builder.compute_program_slice(
        file_path=str(target),
        line_num=17,
        alert_msg="use-after-free: buf freed at line 16 and used at line 17",
    )

    evidence = program_slice["evidence_package"]
    assert evidence["version"] == "source_sink_evidence.v1"
    assert evidence["function"]["name"] == "phase2_use_after_free"
    assert 17 in evidence["sink_lines"]
    assert "buf" in evidence["key_variables"]
    assert evidence["source_sink_paths"]
    assert any("free(buf)" in item["code"] for item in evidence["memory_events"])
    assert program_slice["prompt_context"]
    assert program_slice["token_budget"]["max_prompt_tokens"] == 3000
    assert program_slice["token_budget"]["estimated_context_tokens"] <= ProgramSliceBuilder.MAX_PROMPT_CONTEXT_TOKENS


def test_inference_prompt_inputs_fit_2k_to_4k_budget(monkeypatch):
    monkeypatch.setenv("VULDET_MAX_PROMPT_TOKENS", "2000")
    builder = ProgramSliceBuilder()
    target = ROOT / "data" / "test_codes" / "joern_phase2_high_risk.c"
    program_slice = builder.compute_program_slice(
        file_path=str(target),
        line_num=6,
        alert_msg="buffer-overflow: strcpy(dst, input)",
    )
    oversized_code = program_slice["sliced_code"] + "\n" + ("int filler = 0;\n" * 4000)
    oversized_cve = "CVE context. " * 4000

    agent = InferenceAgent(cve_db_path=str(ROOT / "missing_cve.xlsx"))
    prompt_inputs = agent._build_budgeted_prompt_inputs(program_slice, oversized_code, oversized_cve)

    prompt = agent.prompt_template.format(
        file=str(target),
        line=6,
        func="phase2_buffer_overflow",
        sink="buffer-overflow: strcpy(dst, input)",
        sliced_code=prompt_inputs["sliced_code"],
        source_lines=program_slice["source_lines"],
        sink_lines=program_slice["sink_lines"],
        slice_lines=program_slice["slice_lines"],
        evidence_context=prompt_inputs["evidence_context"],
        cve_intel=prompt_inputs["cve_intel"],
        prompt_token_budget=prompt_inputs["max_prompt_tokens"],
    )

    for _ in range(3):
        estimated = agent._estimate_tokens(prompt)
        if estimated <= prompt_inputs["max_prompt_tokens"]:
            break
        overflow = estimated - prompt_inputs["max_prompt_tokens"]
        code_tokens = agent._estimate_tokens(prompt_inputs["sliced_code"])
        prompt_inputs["sliced_code"] = agent._trim_text_to_tokens(
            prompt_inputs["sliced_code"],
            max(220, code_tokens - overflow - 100),
        )
        prompt = agent.prompt_template.format(
            file=str(target),
            line=6,
            func="phase2_buffer_overflow",
            sink="buffer-overflow: strcpy(dst, input)",
            sliced_code=prompt_inputs["sliced_code"],
            source_lines=program_slice["source_lines"],
            sink_lines=program_slice["sink_lines"],
            slice_lines=program_slice["slice_lines"],
            evidence_context=prompt_inputs["evidence_context"],
            cve_intel=prompt_inputs["cve_intel"],
            prompt_token_budget=prompt_inputs["max_prompt_tokens"],
        )

    assert 2000 <= prompt_inputs["max_prompt_tokens"] <= 4000
    assert agent._estimate_tokens(prompt) <= 2000
    assert json.loads(prompt_inputs["evidence_context"])["source_sink_evidence"]
