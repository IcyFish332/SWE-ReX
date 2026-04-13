import pytest

from swerex.deployment import get_deployment
from swerex.deployment.config import (
    DaytonaDeploymentConfig,
    DockerDeploymentConfig,
    FargateDeploymentConfig,
    InspireSandboxDeploymentConfig,
    LocalDeploymentConfig,
    ModalDeploymentConfig,
    RemoteDeploymentConfig,
)


def test_get_local_deployment():
    from swerex.deployment.local import LocalDeployment

    deployment = get_deployment(LocalDeploymentConfig())
    assert isinstance(deployment, LocalDeployment)


def test_get_docker_deployment():
    from swerex.deployment.docker import DockerDeployment

    deployment = get_deployment(DockerDeploymentConfig(image="test"))
    assert isinstance(deployment, DockerDeployment)


def test_get_modal_deployment():
    pytest.importorskip("modal")
    pytest.importorskip("boto3")
    from swerex.deployment.modal import ModalDeployment

    deployment = get_deployment(ModalDeploymentConfig(image="test"))
    assert isinstance(deployment, ModalDeployment)


def test_get_remote_deployment():
    from swerex.deployment.remote import RemoteDeployment

    deployment = get_deployment(RemoteDeploymentConfig(auth_token="test"))
    assert isinstance(deployment, RemoteDeployment)


def test_get_fargate_deployment():
    pytest.importorskip("boto3")
    from swerex.deployment.fargate import FargateDeployment

    deployment = get_deployment(FargateDeploymentConfig(image="test"))
    assert isinstance(deployment, FargateDeployment)


def test_get_daytona_deployment():
    pytest.importorskip("daytona_sdk")
    from swerex.deployment.daytona import DaytonaDeployment

    deployment = get_deployment(DaytonaDeploymentConfig(image="test"))
    assert isinstance(deployment, DaytonaDeployment)


def test_get_inspire_sandbox_deployment():
    from swerex.deployment.inspire_sandbox import InspireSandboxDeployment

    deployment = get_deployment(InspireSandboxDeploymentConfig(template="test-template"))
    assert isinstance(deployment, InspireSandboxDeployment)


if __name__ == "__main__":
    pytest.main()
