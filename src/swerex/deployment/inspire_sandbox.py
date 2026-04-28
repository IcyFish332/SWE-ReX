import asyncio
import hashlib
import hmac
import logging
import os
import shlex
from typing import Any

from typing_extensions import Self

from swerex.deployment.abstract import AbstractDeployment
from swerex.deployment.config import InspireSandboxDeploymentConfig
from swerex.deployment.hooks.abstract import CombinedDeploymentHook, DeploymentHook
from swerex.exceptions import DeploymentNotStartedError
from swerex.runtime.abstract import IsAliveResponse
from swerex.runtime.config import RemoteRuntimeConfig
from swerex.runtime.remote import RemoteRuntime
from swerex.utils.log import get_logger
from swerex.utils.wait import _wait_until_alive

# ---------------------------------------------------------------------------
# Shared module-level helpers
# ---------------------------------------------------------------------------
# Bumped whenever the bootstrap contract (install steps / start_cmd / ready
# check) changes.  Old templates built under an earlier suffix are left
# alone; consumers recompute template names using this suffix so cached
# templates that no longer match the current contract are naturally
# bypassed.
TEMPLATE_NAME_SUFFIX = "rex1"

_DEFAULT_APT_URL = "http://nexus.sii.shaipower.online/repository/ubuntu/"
_DEFAULT_PYPI_URL = "http://nexus.sii.shaipower.online/repository/pypi/simple"
_DEFAULT_PYPI_TRUSTED_HOSTS: tuple[str, ...] = ("nexus.sii.shaipower.online",)
_DEFAULT_SWEREX_BIN = "/opt/swerex/bin/swerex-remote"
_DEFAULT_SWEREX_VENV = "/opt/swerex/venv"
_DEFAULT_SWEREX_PORT = 8000


def derive_swerex_auth_token(template_name: str, api_key: str | None) -> str:
    """Deterministic per-(template, api_key) swerex ``--auth-token``.

    Returns 32 hex chars (the first half of an HMAC-SHA256).  Both the
    template builder and the Deployment call this with the same inputs so
    the token baked into the template matches the token the Deployment
    presents when connecting.  When ``api_key`` is ``None``/empty, a
    placeholder key keeps the derivation well-defined.
    """
    key_bytes = (api_key or "").encode("utf-8") or b"no-api-key"
    return hmac.new(key_bytes, template_name.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _build_apt_setup(apt_source_url: str | None) -> str:
    """Shell snippet that rewrites Debian/Ubuntu apt sources to ``apt_source_url``.

    When ``apt_source_url`` is empty, returns an empty string so callers can
    skip the mirror-rewrite step entirely.
    """
    if not apt_source_url:
        return ""

    apt_url_ubuntu = apt_source_url
    apt_url_debian = apt_source_url
    apt_url_debian_security = apt_source_url
    if "ubuntu" in apt_source_url:
        apt_url_debian = apt_source_url.replace("ubuntu", "debian")
        apt_url_debian_security = apt_source_url.replace("ubuntu", "debian-security")
    elif "debian" in apt_source_url and "debian-security" not in apt_source_url:
        apt_url_debian_security = apt_source_url.replace("debian", "debian-security")
        apt_url_ubuntu = apt_source_url.replace("debian", "ubuntu")

    return (
        f"(sed -i 's|http://archive.ubuntu.com/ubuntu/|{apt_url_ubuntu}|g' /etc/apt/sources.list 2>/dev/null || true)\n"
        f"(sed -i 's|http://security.ubuntu.com/ubuntu/|{apt_url_ubuntu}|g' /etc/apt/sources.list 2>/dev/null || true)\n"
        f"(sed -i 's|http://deb.debian.org/debian|{apt_url_debian}|g' /etc/apt/sources.list 2>/dev/null || true)\n"
        f"(sed -i 's|http://security.debian.org/debian-security|{apt_url_debian_security}|g' /etc/apt/sources.list 2>/dev/null || true)\n"
        f"(sed -i 's|https://deb.debian.org/debian|{apt_url_debian}|g' /etc/apt/sources.list 2>/dev/null || true)\n"
        f"(sed -i 's|https://security.debian.org/debian-security|{apt_url_debian_security}|g' /etc/apt/sources.list 2>/dev/null || true)\n"
        "if [ -d /etc/apt/sources.list.d ]; then\n"
        "  find /etc/apt/sources.list.d -type f -name '*.sources' -print0 2>/dev/null | \\\n"
        "    xargs -0 -r sed -i "
        f"-e 's|http://deb.debian.org/debian|{apt_url_debian}|g' "
        f"-e 's|https://deb.debian.org/debian|{apt_url_debian}|g' "
        f"-e 's|http://security.debian.org/debian-security|{apt_url_debian_security}|g' "
        f"-e 's|https://security.debian.org/debian-security|{apt_url_debian_security}|g' "
        f"-e 's|http://archive.ubuntu.com/ubuntu/|{apt_url_ubuntu}|g' "
        f"-e 's|http://security.ubuntu.com/ubuntu/|{apt_url_ubuntu}|g' || true\n"
        "fi"
    )


def _build_pip_flags(pypi_index_url: str | None, pypi_trusted_hosts: list[str]) -> str:
    flags: list[str] = []
    if pypi_index_url:
        flags.extend(["-i", pypi_index_url])
    for host in pypi_trusted_hosts:
        flags.extend(["--trusted-host", host])
    return " ".join(shlex.quote(f) for f in flags)


def build_swerex_install_script(
    *,
    apt_source_url: str | None,
    pypi_index_url: str | None,
    pypi_trusted_hosts: list[str],
    swerex_bin: str,
    swerex_venv: str = _DEFAULT_SWEREX_VENV,
) -> str:
    """Bash script that apt-installs python3.11 + pip-installs swe-rex into a venv.

    Intended for use inside ``template.run_cmd(..., user="root")`` at
    template build time.  The platform layer-caches RUN steps, so the
    amortised cost on a rebuild is ~0.
    """
    apt_setup = _build_apt_setup(apt_source_url)
    pip_flags = _build_pip_flags(pypi_index_url, pypi_trusted_hosts)
    bin_dir = os.path.dirname(swerex_bin) or "/opt/swerex/bin"
    venv_q = shlex.quote(swerex_venv)
    bin_q = shlex.quote(swerex_bin)
    bin_dir_q = shlex.quote(bin_dir)

    lines: list[str] = [
        "set -euo pipefail",
    ]
    if apt_setup:
        lines.extend(apt_setup.splitlines())
    lines.extend(
        [
            "DEBIAN_FRONTEND=noninteractive apt-get update",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
            "python3.11 python3.11-venv python3.11-distutils ca-certificates curl",
            f"rm -rf {venv_q}",
            f"python3.11 -m venv {venv_q}",
            f"{venv_q}/bin/python -m pip install --upgrade pip",
            f"{venv_q}/bin/python -m pip install {pip_flags} swe-rex".rstrip(),
            f"mkdir -p {bin_dir_q}",
            f"ln -sf {venv_q}/bin/swerex-remote {bin_q}",
            # Fail fast if the symlink target is missing.
            f"test -x {bin_q}",
        ]
    )
    return "\n".join(lines)


def append_swerex_bootstrap(
    template: Any,  # TemplateBuilder (from inspire_sandbox)
    *,
    token: str,
    swerex_bin: str = _DEFAULT_SWEREX_BIN,
    swerex_port: int = _DEFAULT_SWEREX_PORT,
    apt_source_url: str | None = _DEFAULT_APT_URL,
    pypi_index_url: str | None = _DEFAULT_PYPI_URL,
    pypi_trusted_hosts: list[str] | None = None,
    swerex_venv: str = _DEFAULT_SWEREX_VENV,
) -> Any:  # TemplateFinal (from inspire_sandbox)
    """Chain the swerex install step + ``set_start_cmd`` onto a Template builder.

    Returns the ``TemplateFinal`` instance for use with ``Template.build(...)``.
    """
    from inspire_sandbox import wait_for_url

    hosts = list(pypi_trusted_hosts) if pypi_trusted_hosts is not None else list(
        _DEFAULT_PYPI_TRUSTED_HOSTS
    )
    install_script = build_swerex_install_script(
        apt_source_url=apt_source_url,
        pypi_index_url=pypi_index_url,
        pypi_trusted_hosts=hosts,
        swerex_bin=swerex_bin,
        swerex_venv=swerex_venv,
    )
    start_cmd = (
        f"exec {shlex.quote(swerex_bin)} "
        f"--port {swerex_port} --auth-token {shlex.quote(token)}"
    )
    ready_cmd = wait_for_url(f"http://localhost:{swerex_port}/is_alive", 200)
    return (
        template
        .set_user("root")
        .run_cmd(install_script, user="root")
        .set_start_cmd(start_cmd, ready_cmd)
    )


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------
class InspireSandboxDeployment(AbstractDeployment):
    """Managed deployment backed by Inspire Sandbox.

    The bootstrap (apt install python3.11, pip install swe-rex, exec swerex-remote)
    is baked into the template at build time via
    :func:`append_swerex_bootstrap`.  ``_start_once`` therefore only needs
    to create the sandbox and connect a :class:`RemoteRuntime` — the
    service is already listening inside the snapshot.
    """

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        **kwargs: Any,
    ):
        self._config = InspireSandboxDeploymentConfig(**kwargs)
        self._runtime: RemoteRuntime | None = None
        self._sandbox: Any | None = None
        self._auth_token: str | None = None
        self.logger = logger or get_logger("rex-deploy")
        self._hooks = CombinedDeploymentHook()

    def add_hook(self, hook: DeploymentHook):
        self._hooks.add_hook(hook)

    @classmethod
    def from_config(cls, config: InspireSandboxDeploymentConfig) -> Self:
        return cls(**config.model_dump())

    # -- helpers ------------------------------------------------------------
    def _resolve_auth_token(self) -> str:
        if self._config.swerex_auth_token:
            return self._config.swerex_auth_token
        if not self._config.template:
            # When attaching to an existing sandbox by ID (no template), we
            # can't derive a token — caller must set swerex_auth_token.
            raise ValueError(
                "swerex_auth_token must be set explicitly when connecting "
                "to an existing sandbox_id without a template name."
            )
        api_key = self._config.api_key or os.getenv("SBX_API_KEY")
        return derive_swerex_auth_token(self._config.template, api_key)

    def _sdk_api_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self._config.api_key:
            params["api_key"] = self._config.api_key
        if self._config.api_url:
            params["api_url"] = self._config.api_url
        if self._config.request_timeout is not None:
            params["request_timeout"] = self._config.request_timeout
        if self._config.verify_ssl is not None:
            params["verify_ssl"] = self._config.verify_ssl
        if self._config.headers:
            params["headers"] = self._config.headers
        return params

    def _network_config(self) -> dict[str, Any] | None:
        network: dict[str, Any] = {}
        if not self._config.allow_public_traffic:
            network["allow_public_traffic"] = False
        return network or None

    def _runtime_headers(self) -> dict[str, str]:
        headers = dict(self._config.runtime_headers)
        if (
            not self._config.allow_public_traffic
            and self._sandbox is not None
            and getattr(self._sandbox, "traffic_access_token", None)
        ):
            headers.setdefault("sbx-traffic-access-token", self._sandbox.traffic_access_token)
        return headers

    # -- lifecycle ----------------------------------------------------------
    async def is_alive(self, *, timeout: float | None = None) -> IsAliveResponse:
        if self._runtime is None or self._sandbox is None:
            raise DeploymentNotStartedError()
        try:
            if not self._sandbox.is_running(request_timeout=self._config.request_timeout):
                return IsAliveResponse(is_alive=False, message="Inspire sandbox is not running")
        except Exception as e:
            return IsAliveResponse(is_alive=False, message=f"Failed to query sandbox state: {e}")
        return await self._runtime.is_alive(timeout=timeout)

    async def _wait_until_alive(self, timeout: float):
        return await _wait_until_alive(
            self.is_alive, timeout=timeout, function_timeout=self._config.runtime_timeout
        )

    async def _start_once(self):
        """Create (or connect to) a sandbox and attach a RemoteRuntime.

        No post-create ``commands.run`` is needed: swerex-remote is already
        running inside the template snapshot.
        """
        from inspire_sandbox import Sandbox

        self._hooks.on_custom_step("Allocating Inspire sandbox")
        sdk_params = self._sdk_api_params()
        if self._config.sandbox_id is not None:
            self._sandbox = Sandbox.connect(
                self._config.sandbox_id,
                timeout=self._config.sandbox_timeout,
                **sdk_params,
            )
        else:
            self._sandbox = Sandbox.create(
                template=self._config.template,
                timeout=self._config.sandbox_timeout,
                metadata=self._config.metadata or None,
                envs=self._config.envs or None,
                secure=self._config.secure,
                allow_internet_access=self._config.allow_internet_access,
                network=self._network_config(),
                **sdk_params,
            )

        self._auth_token = self._resolve_auth_token()

        scheme = "http" if self._sandbox.connection_config.debug else "https"
        host = f"{scheme}://{self._sandbox.get_host(self._config.swerex_port)}"
        self._hooks.on_custom_step("Connecting RemoteRuntime")
        self._runtime = RemoteRuntime.from_config(
            RemoteRuntimeConfig(
                host=host,
                port=None,
                timeout=self._config.runtime_timeout,
                auth_token=self._auth_token,
                extra_headers=self._runtime_headers(),
                upload_num_retries=self._config.upload_num_retries,
                upload_retry_delay=self._config.upload_retry_delay,
                upload_backoff_max=self._config.upload_backoff_max,
                request_num_retries=self._config.request_num_retries,
            )
        )

        try:
            await self._wait_until_alive(timeout=self._config.startup_timeout)
        except Exception:
            await self.stop()
            raise

    async def start(self):
        if self._runtime is not None and self._sandbox is not None:
            self.logger.warning("Deployment is already started. Ignoring duplicate start() call.")
            return

        max_attempts = 1 + self._config.start_retries
        last_error: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                await self._start_once()
                return
            except (TimeoutError, RuntimeError) as e:
                last_error = e
                self.logger.warning(
                    "Bootstrap attempt %d/%d failed: %s",
                    attempt, max_attempts, e,
                )
                await self.stop()
                if attempt < max_attempts:
                    self.logger.info("Retrying sandbox creation...")
                self._runtime = None
                self._sandbox = None
                self._auth_token = None

        raise last_error  # type: ignore[misc]

    async def stop(self):
        if self._runtime is not None:
            try:
                if self._config.close_timeout is None:
                    await self._runtime.close()
                else:
                    await asyncio.wait_for(self._runtime.close(), timeout=self._config.close_timeout)
            except (Exception, asyncio.TimeoutError):
                self.logger.warning("Failed to close runtime cleanly", exc_info=False)
            finally:
                self._runtime = None

        if self._sandbox is not None and self._config.stop_policy == "kill":
            try:
                self._sandbox.kill(**self._sdk_api_params())
            except Exception:
                self.logger.warning("Failed to kill sandbox cleanly", exc_info=False)

        self._sandbox = None
        self._auth_token = None

    @property
    def runtime(self) -> RemoteRuntime:
        if self._runtime is None:
            raise DeploymentNotStartedError()
        return self._runtime
