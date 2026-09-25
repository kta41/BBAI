from bbai.context.builder import ContextInput, build_context


def test_build_context_contains_required_sections() -> None:
    prompt = build_context(
        ContextInput(
            target="example.com",
            scope="example.com, *.example.com",
            assets="domain: example.com",
            endpoints="GET https://example.com/",
            recon="HTTP on 443",
            http_observations="200 OK on /",
            previous_findings="No previous findings",
            observations="O-001: Header is unusual",
            hypotheses="H-001: The endpoint may expose debug data",
            evidence="Request captured from /api",
            question="What should we inspect next?",
        )
    )

    assert "TARGET" in prompt
    assert "SCOPE" in prompt
    assert "ASSETS" in prompt
    assert "ENDPOINTS" in prompt
    assert "HTTP OBSERVATIONS" in prompt
    assert "PREVIOUS FINDINGS" in prompt
    assert "OBSERVATIONS" in prompt
    assert "HYPOTHESES" in prompt
    assert "EVIDENCE" in prompt
    assert "USER QUESTION" in prompt
    assert "example.com" in prompt
    assert "What should we inspect next?" in prompt
