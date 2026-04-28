"""Tests for Option-A-style swerex bootstrap helpers in inspire_sandbox.py.

These tests are written against the new contract (token baked into template at
build time, service started via `Template.set_start_cmd`). Prior to the
Option-A refactor, the imports below will fail — that is the expected RED
state.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("inspire_sandbox")


def test_derive_swerex_auth_token_is_deterministic():
    from swerex.deployment.inspire_sandbox import derive_swerex_auth_token

    a = derive_swerex_auth_token("swebench-django-11149-g-c4-rex1", "api-key-xyz")
    b = derive_swerex_auth_token("swebench-django-11149-g-c4-rex1", "api-key-xyz")
    assert a == b
    # 32 hex chars (128 bits, half an HMAC-SHA256)
    assert len(a) == 32
    assert all(c in "0123456789abcdef" for c in a)


def test_derive_swerex_auth_token_depends_on_api_key():
    from swerex.deployment.inspire_sandbox import derive_swerex_auth_token

    a = derive_swerex_auth_token("swebench-x-rex1", "key-A")
    b = derive_swerex_auth_token("swebench-x-rex1", "key-B")
    assert a != b


def test_derive_swerex_auth_token_depends_on_template_name():
    from swerex.deployment.inspire_sandbox import derive_swerex_auth_token

    a = derive_swerex_auth_token("swebench-x-rex1", "key-A")
    b = derive_swerex_auth_token("swebench-y-rex1", "key-A")
    assert a != b


def test_derive_swerex_auth_token_handles_empty_api_key():
    from swerex.deployment.inspire_sandbox import derive_swerex_auth_token

    # Must not raise when api_key is None / "" (fallback deterministic).
    a = derive_swerex_auth_token("swebench-x-rex1", None)
    b = derive_swerex_auth_token("swebench-x-rex1", "")
    assert len(a) == 32 and len(b) == 32


def test_template_name_suffix_constant():
    from swerex.deployment.inspire_sandbox import TEMPLATE_NAME_SUFFIX

    assert TEMPLATE_NAME_SUFFIX == "rex1"


def test_append_swerex_bootstrap_builds_valid_template():
    from inspire_sandbox import Template
    from inspire_sandbox.template.main import TemplateBase

    from swerex.deployment.inspire_sandbox import append_swerex_bootstrap

    builder = Template().from_image("ubuntu:24.04")
    final = append_swerex_bootstrap(
        builder,
        token="deadbeefcafefeed" * 2,
        swerex_bin="/opt/swerex/bin/swerex-remote",
        swerex_port=8000,
        apt_source_url="http://nexus.example.com/repository/ubuntu/",
        pypi_index_url="http://nexus.example.com/repository/pypi/simple",
        pypi_trusted_hosts=["nexus.example.com"],
    )
    # Must return TemplateFinal (chain-terminating type).
    from inspire_sandbox.template.main import TemplateFinal
    assert isinstance(final, TemplateFinal)

    serialized = json.loads(TemplateBase.to_json(final))
    assert serialized["fromImage"] == "ubuntu:24.04"
    assert "startCmd" in serialized
    assert "readyCmd" in serialized

    # Token must be present in startCmd; fake token used here should survive quoting.
    assert "deadbeefcafefeed" * 2 in serialized["startCmd"]
    # --port and --auth-token flags present.
    assert "--port 8000" in serialized["startCmd"]
    assert "--auth-token" in serialized["startCmd"]
    # swerex binary path referenced.
    assert "/opt/swerex/bin/swerex-remote" in serialized["startCmd"]
    # ready_cmd should curl /is_alive.
    assert "/is_alive" in serialized["readyCmd"]
    assert "localhost:8000" in serialized["readyCmd"]
    assert "curl" in serialized["readyCmd"]

    # Install script must be captured in steps (as a RUN instruction).
    run_steps = [s for s in serialized["steps"] if s["type"] == "RUN"]
    assert run_steps, "expected at least one RUN step for the install script"
    joined = "\n".join(" ".join(s["args"]) for s in run_steps)
    assert "python3.11" in joined
    assert "swe-rex" in joined or "swerex" in joined
    # apt mirror substitution should appear somewhere.
    assert "nexus.example.com" in joined


def test_append_swerex_bootstrap_different_ports():
    from inspire_sandbox import Template
    from inspire_sandbox.template.main import TemplateBase

    from swerex.deployment.inspire_sandbox import append_swerex_bootstrap

    builder = Template().from_image("ubuntu:24.04")
    final = append_swerex_bootstrap(
        builder,
        token="t" * 32,
        swerex_bin="/opt/swerex/bin/swerex-remote",
        swerex_port=9001,
    )
    serialized = json.loads(TemplateBase.to_json(final))
    assert "--port 9001" in serialized["startCmd"]
    assert "localhost:9001" in serialized["readyCmd"]


def test_config_swerex_auth_token_field_and_default_traffic_flag():
    """allow_public_traffic default must flip to False under Option A,
    and swerex_auth_token field must exist (empty = derive)."""
    from swerex.deployment.config import InspireSandboxDeploymentConfig

    cfg = InspireSandboxDeploymentConfig(template="test-template")
    assert cfg.allow_public_traffic is False
    assert cfg.swerex_auth_token == ""

    cfg2 = InspireSandboxDeploymentConfig(
        template="test-template",
        swerex_auth_token="custom-token-123",
    )
    assert cfg2.swerex_auth_token == "custom-token-123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
