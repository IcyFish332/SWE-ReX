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

    a = derive_swerex_auth_token("swebench-django-11149-g-c4-rex3")
    b = derive_swerex_auth_token("swebench-django-11149-g-c4-rex3")
    assert a == b
    # 32 hex chars (128 bits, half an HMAC-SHA256)
    assert len(a) == 32
    assert all(c in "0123456789abcdef" for c in a)


def test_derive_swerex_auth_token_depends_on_template_name():
    from swerex.deployment.inspire_sandbox import derive_swerex_auth_token

    a = derive_swerex_auth_token("swebench-x-rex3")
    b = derive_swerex_auth_token("swebench-y-rex3")
    assert a != b


def test_derive_swerex_auth_token_independent_of_environment():
    """The token must not depend on SBX_API_KEY or any other environment state.

    Regression test for an earlier contract where the HMAC key was
    ``SBX_API_KEY``: a silent rotation of the key (e.g. platform
    re-provisioning a notebook) made every pre-built template
    un-connectable.  The current derivation uses only ``template_name``
    and a fixed module-level salt.
    """
    import os

    from swerex.deployment.inspire_sandbox import derive_swerex_auth_token

    prev = os.environ.get("SBX_API_KEY")
    try:
        os.environ["SBX_API_KEY"] = "key-A"
        a = derive_swerex_auth_token("swebench-x-rex3")
        os.environ["SBX_API_KEY"] = "key-B"
        b = derive_swerex_auth_token("swebench-x-rex3")
    finally:
        if prev is None:
            os.environ.pop("SBX_API_KEY", None)
        else:
            os.environ["SBX_API_KEY"] = prev
    assert a == b


def test_template_name_suffix_constant():
    from swerex.deployment.inspire_sandbox import TEMPLATE_NAME_SUFFIX

    assert TEMPLATE_NAME_SUFFIX == "rex3"


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
    # ready_cmd should curl /is_alive AND carry X-API-Key so swerex-remote's
    # authenticate() middleware lets it through.
    assert "/is_alive" in serialized["readyCmd"]
    assert "localhost:8000" in serialized["readyCmd"]
    assert "curl" in serialized["readyCmd"]
    assert "X-API-Key" in serialized["readyCmd"]
    assert "deadbeefcafefeed" * 2 in serialized["readyCmd"]

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
