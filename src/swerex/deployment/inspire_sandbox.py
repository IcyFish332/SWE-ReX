import asyncio
import logging
import shlex
import time
import uuid
from typing import Any

from typing_extensions import Self

from swerex import PACKAGE_NAME, REMOTE_EXECUTABLE_NAME
from swerex.deployment.abstract import AbstractDeployment
from swerex.deployment.config import InspireSandboxDeploymentConfig
from swerex.deployment.hooks.abstract import CombinedDeploymentHook, DeploymentHook
from swerex.exceptions import DeploymentNotStartedError
from swerex.runtime.abstract import IsAliveResponse
from swerex.runtime.config import RemoteRuntimeConfig
from swerex.runtime.remote import RemoteRuntime
from swerex.utils.log import get_logger
from swerex.utils.wait import _wait_until_alive


class InspireSandboxDeployment(AbstractDeployment):
    """Managed deployment backed by Inspire Sandbox."""

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        **kwargs: Any,
    ):
        self._config = InspireSandboxDeploymentConfig(**kwargs)
        self._runtime: RemoteRuntime | None = None
        self._sandbox: Any | None = None
        self._command_handle: Any | None = None
        self._auth_token: str | None = None
        self.logger = logger or get_logger("rex-deploy")
        self._hooks = CombinedDeploymentHook()

    def add_hook(self, hook: DeploymentHook):
        self._hooks.add_hook(hook)

    @classmethod
    def from_config(cls, config: InspireSandboxDeploymentConfig) -> Self:
        return cls(**config.model_dump())

    def _get_token(self) -> str:
        return str(uuid.uuid4())

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

    def _command_envs(self) -> dict[str, str] | None:
        envs = dict(self._config.bootstrap_envs)
        if self._config.pypi_index_url:
            envs.setdefault("PIP_INDEX_URL", self._config.pypi_index_url)
        if self._config.pypi_trusted_hosts:
            envs.setdefault("PIP_TRUSTED_HOST", " ".join(self._config.pypi_trusted_hosts))
        return envs or None

    def _get_apt_setup_cmd(self) -> str:
        apt_url = self._config.apt_source_url
        if not apt_url:
            return ""

        apt_url_ubuntu = apt_url
        apt_url_debian = apt_url
        apt_url_debian_security = apt_url
        if "ubuntu" in apt_url:
            apt_url_debian = apt_url.replace("ubuntu", "debian")
            apt_url_debian_security = apt_url.replace("ubuntu", "debian-security")
        elif "debian" in apt_url and "debian-security" not in apt_url:
            apt_url_debian_security = apt_url.replace("debian", "debian-security")
            apt_url_ubuntu = apt_url.replace("debian", "ubuntu")

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

    def _get_pip_install_flags(self) -> str:
        flags: list[str] = []
        if self._config.pypi_index_url:
            flags.extend(["-i", self._config.pypi_index_url])
        for host in self._config.pypi_trusted_hosts:
            flags.extend(["--trusted-host", host])
        return " ".join(shlex.quote(flag) for flag in flags)

    def _get_swerex_start_cmd(self, token: str) -> str:
        port = self._config.swerex_port
        apt_setup = self._get_apt_setup_cmd()
        pip_install_flags = self._get_pip_install_flags()
        preferred_bin = shlex.quote(self._config.swerex_bin)
        package = shlex.quote(PACKAGE_NAME)
        executable = shlex.quote(REMOTE_EXECUTABLE_NAME)
        venv_dir = "/tmp/swerex-venv"
        lines = [
            "set -euo pipefail",
            f"REX_ARGS='--port {port} --auth-token {token}'",
            "ensure_python_bin() {",
            "  command -v python3 || command -v python || true",
            "}",
            "python_is_modern() {",
            '  "$1" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1',
            "}",
            "ensure_pipx() {",
            "  if command -v pipx >/dev/null 2>&1; then",
            "    return 0",
            "  fi",
            "  if ! command -v apt-get >/dev/null 2>&1; then",
            "    return 1",
            "  fi",
        ]
        if apt_setup:
            lines.extend(apt_setup.splitlines())
        lines.extend(
            [
                "  apt-get update",
                "  apt-get install -y pipx",
                "  command -v pipx >/dev/null 2>&1",
                "}",
                "try_with_pipx() {",
                "  local python_bin=\"$1\"",
                "  if ! ensure_pipx; then",
                "    return 1",
                "  fi",
                f"  PIPX_DEFAULT_PYTHON=\"$python_bin\" pipx run --spec {package} {REMOTE_EXECUTABLE_NAME} $REX_ARGS",
                "}",
                "try_with_venv() {",
                "  local python_bin=\"$1\"",
                f"  rm -rf {shlex.quote(venv_dir)}",
                f"  \"$python_bin\" -m venv {shlex.quote(venv_dir)}",
                f"  \"{venv_dir}/bin/python\" -m pip install --upgrade pip",
                f"  \"{venv_dir}/bin/python\" -m pip install {pip_install_flags} {package}".rstrip(),
                f"  exec \"{venv_dir}/bin/{REMOTE_EXECUTABLE_NAME}\" $REX_ARGS",
                "}",
                f"if [ -x {preferred_bin} ]; then",
                f"  exec {preferred_bin} $REX_ARGS",
                "fi",
                f"if command -v {executable} >/dev/null 2>&1; then",
                f"  exec {executable} $REX_ARGS",
                "fi",
                'PYTHON_BIN="$(ensure_python_bin)"',
                'if [ -n "${PYTHON_BIN}" ] && python_is_modern "${PYTHON_BIN}"; then',
                '  if try_with_pipx "${PYTHON_BIN}"; then',
                "    exit 0",
                "  fi",
                '  try_with_venv "${PYTHON_BIN}"',
                "fi",
                "if command -v python3.11 >/dev/null 2>&1; then",
                "  PYTHON_BIN=python3.11",
                "else",
                "  if ! command -v apt-get >/dev/null 2>&1; then",
                '    echo "python3.11 not available and apt-get is missing" >&2',
                "    exit 1",
                "  fi",
            ]
        )
        if apt_setup:
            lines.extend(apt_setup.splitlines())
        lines.extend(
            [
                "  apt-get update",
                "  apt-get install -y python3.11 python3.11-venv pipx",
                "  PYTHON_BIN=python3.11",
                "fi",
                'if ! python_is_modern "${PYTHON_BIN}"; then',
                '  echo "No compatible Python (>=3.10) available for SWE-ReX bootstrap" >&2',
                "  exit 1",
                "fi",
                'if try_with_pipx "${PYTHON_BIN}"; then',
                "  exit 0",
                "fi",
                'try_with_venv "${PYTHON_BIN}"',
            ]
        )
        script = "\n".join(lines)
        return "bash -lc " + shlex.quote(script)

    def _get_bootstrap_output(self) -> str:
        """Read accumulated stdout/stderr from the bootstrap command handle."""
        if self._command_handle is None:
            return ""
        stdout = getattr(self._command_handle, "_stdout", "") or ""
        stderr = getattr(self._command_handle, "_stderr", "") or ""
        parts = []
        if stdout:
            parts.append(f"stdout:\n{stdout}")
        if stderr:
            parts.append(f"stderr:\n{stderr}")
        return "\n".join(parts)

    async def is_alive(self, *, timeout: float | None = None) -> IsAliveResponse:
        if self._runtime is None or self._sandbox is None:
            raise DeploymentNotStartedError()
        try:
            if not self._sandbox.is_running(request_timeout=self._config.request_timeout):
                return IsAliveResponse(is_alive=False, message="Inspire sandbox is not running")
        except Exception as e:
            return IsAliveResponse(is_alive=False, message=f"Failed to query sandbox state: {e}")
        if self._command_handle is not None:
            exit_code = getattr(self._command_handle, "exit_code", None)
            if exit_code is not None:
                output = self._get_bootstrap_output()
                msg = f"Bootstrap process terminated with exit code {exit_code}.\n{output}"
                raise RuntimeError(msg)
        return await self._runtime.is_alive(timeout=timeout)

    async def _wait_until_alive(self, timeout: float):
        return await _wait_until_alive(self.is_alive, timeout=timeout, function_timeout=self._config.runtime_timeout)

    async def _start_once(self):
        """Create a sandbox, run the bootstrap command, and wait for the runtime."""
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

        self._auth_token = self._get_token()
        self._hooks.on_custom_step("Starting SWE-ReX inside sandbox")
        self._command_handle = self._sandbox.commands.run(
            self._get_swerex_start_cmd(self._auth_token),
            background=True,
            envs=self._command_envs(),
            user=self._config.bootstrap_user,
            timeout=None,
            request_timeout=self._config.request_timeout,
        )

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
            )
        )

        t0 = time.time()
        try:
            await self._wait_until_alive(timeout=self._config.startup_timeout)
        except TimeoutError as e:
            output = self._get_bootstrap_output()
            self.logger.error(
                "SWE-ReX bootstrap did not start within timeout. Bootstrap output:\n%s",
                output or "(no output captured)",
            )
            await self.stop()
            raise
        except Exception:
            await self.stop()
            raise
        self.logger.info("Runtime started in %.2fs", time.time() - t0)

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
                self._command_handle = None
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

        if self._command_handle is not None and self._config.stop_policy == "keep":
            try:
                self._command_handle.kill()
            except Exception:
                self.logger.warning("Failed to kill sandbox background command", exc_info=False)
            finally:
                self._command_handle = None

        if self._sandbox is not None and self._config.stop_policy == "kill":
            try:
                self._sandbox.kill(**self._sdk_api_params())
            except Exception:
                self.logger.warning("Failed to kill sandbox cleanly", exc_info=False)

        self._sandbox = None
        self._command_handle = None
        self._auth_token = None

    @property
    def runtime(self) -> RemoteRuntime:
        if self._runtime is None:
            raise DeploymentNotStartedError()
        return self._runtime
