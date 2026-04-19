from pathlib import PurePath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from swerex.deployment.abstract import AbstractDeployment


class LocalDeploymentConfig(BaseModel):
    """Configuration for running locally."""

    type: Literal["local"] = "local"
    """Discriminator for (de)serialization/CLI. Do not change."""

    model_config = ConfigDict(extra="forbid")

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.local import LocalDeployment

        return LocalDeployment.from_config(self)


class DockerDeploymentConfig(BaseModel):
    """Configuration for running locally in a Docker or Podman container."""

    image: str = "python:3.11"
    """The name of the container image to use."""
    port: int | None = None
    """The port that the container connects to. If None, a free port is found."""
    docker_args: list[str] = []
    """Additional arguments to pass to the container run command. If --platform is specified here, it will be moved to the platform field."""
    startup_timeout: float = 180.0
    """The time to wait for the runtime to start."""
    pull: Literal["never", "always", "missing"] = "missing"
    """When to pull container images."""
    remove_images: bool = False
    """Whether to remove the image after it has stopped."""
    python_standalone_dir: str | None = None
    """The directory to use for the python standalone."""
    platform: str | None = None
    """The platform to use for the container image."""
    remove_container: bool = True
    """Whether to remove the container after it has stopped."""
    container_runtime: Literal["docker", "podman"] = "docker"
    """The container runtime to use (docker or podman)."""
    exec_shell: list[str] = ["/bin/sh", "-c"]
    """The shell executable and arguments to use for running commands."""
    docker_internal_host: str = "http://127.0.0.1"
    """The host to use for connecting to the runtime.
    In most cases you can leave this as-is, however for docker-in-docker
    setups you might have to set it to http://host.docker.internal/ 
    (see https://github.com/SWE-agent/SWE-ReX/issues/253 for more information).
    """

    type: Literal["docker"] = "docker"
    """Discriminator for (de)serialization/CLI. Do not change."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    def validate_platform_args(cls, data: dict) -> dict:
        if not isinstance(data, dict):
            return data

        docker_args = data.get("docker_args", [])
        platform = data.get("platform")

        platform_arg_idx = next((i for i, arg in enumerate(docker_args) if arg.startswith("--platform")), -1)

        if platform_arg_idx != -1:
            if platform is not None:
                msg = "Cannot specify platform both via 'platform' field and '--platform' in docker_args"
                raise ValueError(msg)
            # Extract platform value from --platform argument
            if "=" in docker_args[platform_arg_idx]:
                # Handle case where platform is specified as --platform=value
                data["platform"] = docker_args[platform_arg_idx].split("=", 1)[1]
                data["docker_args"] = docker_args[:platform_arg_idx] + docker_args[platform_arg_idx + 1 :]
            elif platform_arg_idx + 1 < len(docker_args):
                data["platform"] = docker_args[platform_arg_idx + 1]
                # Remove the --platform and its value from docker_args
                data["docker_args"] = docker_args[:platform_arg_idx] + docker_args[platform_arg_idx + 2 :]
            else:
                msg = "--platform argument must be followed by a value"
                raise ValueError(msg)

        return data

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.docker import DockerDeployment

        return DockerDeployment.from_config(self)


class ModalDeploymentConfig(BaseModel):
    """Configuration for running on Modal."""

    image: str | PurePath = "python:3.11"
    """Image to use for the deployment."""

    startup_timeout: float = 180.0
    """The time to wait for the runtime to start."""

    runtime_timeout: float = 60.0
    """Runtime timeout (default timeout for all runtime requests)
    """

    deployment_timeout: float = 3600.0
    """Kill deployment after this many seconds no matter what.
    This is a useful killing switch to ensure that you don't spend too 
    much money on modal.
    """

    modal_sandbox_kwargs: dict[str, Any] = {}
    """Additional arguments to pass to `modal.Sandbox.create`"""

    type: Literal["modal"] = "modal"
    """Discriminator for (de)serialization/CLI. Do not change."""

    install_pipx: bool = True
    """Whether to install pipx with apt in the container.
    This is enabled by default so we can fall back to installing swe-rex
    with pipx if the image does not have it. However, depending on your image,
    installing pipx might fail (or be slow).
    """

    model_config = ConfigDict(extra="forbid")

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.modal import ModalDeployment

        return ModalDeployment.from_config(self)


class FargateDeploymentConfig(BaseModel):
    """Configuration for running on AWS Fargate."""

    image: str = "python:3.11"
    port: int = 8880
    cluster_name: str = "swe-rex-cluster"
    execution_role_prefix: str = "swe-rex-execution-role"
    task_definition_prefix: str = "swe-rex-task"
    log_group: str | None = "/ecs/swe-rex-deployment"
    security_group_prefix: str = "swe-rex-deployment-sg"
    fargate_args: dict[str, str] = {}
    container_timeout: float = 60 * 15
    runtime_timeout: float = 60

    type: Literal["fargate"] = "fargate"
    """Discriminator for (de)serialization/CLI. Do not change."""

    model_config = ConfigDict(extra="forbid")

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.fargate import FargateDeployment

        return FargateDeployment.from_config(self)


class RemoteDeploymentConfig(BaseModel):
    """Configuration for `RemoteDeployment`, a wrapper around `RemoteRuntime` that can be used to connect to any
    swerex server.
    """

    auth_token: str
    """The token to use for authentication."""
    host: str = "http://127.0.0.1"
    """The host to connect to."""
    port: int | None = None
    """The port to connect to."""
    timeout: float = 0.15

    type: Literal["remote"] = "remote"
    """Discriminator for (de)serialization/CLI. Do not change."""

    model_config = ConfigDict(extra="forbid")

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.remote import RemoteDeployment

        return RemoteDeployment.from_config(self)


class DummyDeploymentConfig(BaseModel):
    """Configuration for `DummyDeployment`, a deployment that is used for testing."""

    type: Literal["dummy"] = "dummy"
    """Discriminator for (de)serialization/CLI. Do not change."""

    model_config = ConfigDict(extra="forbid")

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.dummy import DummyDeployment

        return DummyDeployment.from_config(self)


class DaytonaDeploymentConfig(BaseModel):
    """Configuration for Daytona deployment."""

    api_key: str = Field(default="", description="Daytona API key for authentication")
    target: str = Field(default="us", description="Daytona target region (us, eu, etc.)")
    port: int = Field(default=8000, description="Port to expose for the SWE Rex server")
    container_timeout: float = Field(default=60 * 15, description="Timeout for the container")
    runtime_timeout: float = Field(default=60, description="Timeout for the runtime")
    image: str = Field(default="python:3.11", description="Image to use for the sandbox")

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.daytona import DaytonaDeployment

        return DaytonaDeployment.from_config(self)


class InspireSandboxDeploymentConfig(BaseModel):
    """Configuration for running inside Inspire Sandbox."""

    template: str | None = None
    """Sandbox template name or ID used when creating a new sandbox."""

    sandbox_id: str | None = None
    """Existing sandbox ID to connect to instead of creating a new sandbox."""

    sandbox_timeout: int | None = 3600
    """Sandbox lifetime in seconds when creating or reconnecting."""

    startup_timeout: float = 600.0
    """The time to wait for the SWE-ReX runtime to start.

    Bootstrap may need to install python3.11 via apt and swe-rex via pip,
    which can take several minutes on the Inspire platform.
    """

    runtime_timeout: float = 60.0
    """Default timeout for RemoteRuntime requests."""

    swerex_port: int = 8000
    """Port inside the sandbox used by the SWE-ReX server."""

    secure: bool = True
    """Whether to secure the Inspire sandbox controller API."""

    allow_internet_access: bool = True
    """Whether the sandbox can reach the public internet."""

    allow_public_traffic: bool = True
    """Whether the public sandbox host can be accessed without the platform traffic token."""

    metadata: dict[str, str] = Field(default_factory=dict)
    """Metadata attached to newly created sandboxes."""

    envs: dict[str, str] = Field(default_factory=dict)
    """Environment variables set when creating a new sandbox."""

    bootstrap_envs: dict[str, str] = Field(default_factory=dict)
    """Environment variables passed only to the SWE-ReX bootstrap command."""

    bootstrap_user: str | None = "root"
    """User used to execute the SWE-ReX bootstrap command inside the sandbox."""

    api_key: str | None = None
    """Override Inspire Sandbox API key. Falls back to SBX_API_KEY."""

    api_url: str | None = None
    """Override Inspire Sandbox API URL. Falls back to SBX_API_URL."""

    request_timeout: float | None = None
    """Optional request timeout passed to Inspire Sandbox SDK calls."""

    verify_ssl: bool | None = None
    """Optional SSL verification override for Inspire Sandbox SDK calls."""

    headers: dict[str, str] = Field(default_factory=dict)
    """Additional headers passed to Inspire Sandbox control-plane API calls."""

    runtime_headers: dict[str, str] = Field(default_factory=dict)
    """Additional headers passed to the SWE-ReX runtime endpoint."""

    swerex_bin: str = "/opt/swerex/bin/swerex-remote"
    """Preferred path to a preinstalled SWE-ReX server binary inside the sandbox."""

    apt_source_url: str | None = "http://nexus.sii.shaipower.online/repository/ubuntu/"
    """Ubuntu/Debian mirror used when bootstrap needs apt-get.

    Defaults to the Inspire-internal Nexus mirror, which is the only
    apt source reliably reachable from inside Inspire sandboxes.
    """

    pypi_index_url: str | None = "http://nexus.sii.shaipower.online/repository/pypi/simple"
    """PyPI index URL used during SWE-ReX bootstrap installation.

    Defaults to the Inspire-internal Nexus mirror.  External mirrors
    (pypi.org, Aliyun, Tsinghua, etc.) are not reachable from sandboxes.
    """

    pypi_trusted_hosts: list[str] = Field(default_factory=lambda: ["nexus.sii.shaipower.online"])
    """Trusted hosts passed to pip and pipx during SWE-ReX bootstrap installation.

    The default Nexus mirror uses plain HTTP, so its hostname must be
    listed as a trusted host.
    """

    close_timeout: float | None = 10.0
    """Timeout in seconds for closing the RemoteRuntime connection during stop().

    If None, waits indefinitely. Prevents stop() from blocking forever
    when the runtime is unresponsive.
    """

    upload_num_retries: int = 0
    """Number of retries for file uploads to the runtime. 0 means no retry."""

    upload_retry_delay: float = 0.5
    """Initial delay in seconds between upload retries."""

    upload_backoff_max: float = 5.0
    """Maximum delay in seconds between upload retries (exponential backoff cap)."""

    request_num_retries: int = 0
    """Number of retries for runtime API requests (run_in_session, create_session, etc.).
    0 means no retry. Helps survive transient 502/504 gateway errors."""

    stop_policy: Literal["kill", "keep"] = "kill"
    """Whether stopping the deployment kills the sandbox or leaves it running."""

    start_retries: int = 0
    """Number of times to retry sandbox creation + bootstrap if the initial
    attempt fails (e.g. TimeoutError).  0 means no retry (single attempt)."""

    spec_code: str = "g.c4"
    """Sandbox resource specification code used when building templates.

    Available specs: g.c1 (1 vCPU / 4 GB), g.c2 (2 vCPU / 8 GB),
    g.c4 (4 vCPU / 16 GB).
    """

    type: Literal["inspire_sandbox"] = "inspire_sandbox"
    """Discriminator for (de)serialization/CLI. Do not change."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_target(self):
        if bool(self.template) == bool(self.sandbox_id):
            msg = "Specify exactly one of 'template' or 'sandbox_id'"
            raise ValueError(msg)
        if self.template and "/" in self.template:
            msg = (
                f"Template name must not contain '/': {self.template!r}. "
                "The Inspire Sandbox API rejects template names with slashes."
            )
            raise ValueError(msg)
        return self

    def get_deployment(self) -> AbstractDeployment:
        from swerex.deployment.inspire_sandbox import InspireSandboxDeployment

        return InspireSandboxDeployment.from_config(self)


DeploymentConfig = (
    LocalDeploymentConfig
    | DockerDeploymentConfig
    | ModalDeploymentConfig
    | FargateDeploymentConfig
    | RemoteDeploymentConfig
    | DummyDeploymentConfig
    | DaytonaDeploymentConfig
    | InspireSandboxDeploymentConfig
)
"""Union of all deployment configurations. Useful for type hints."""


def get_deployment(
    config: DeploymentConfig,
) -> AbstractDeployment:
    return config.get_deployment()
