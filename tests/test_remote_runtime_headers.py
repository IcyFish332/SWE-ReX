from swerex.runtime.remote import RemoteRuntime


def test_remote_runtime_merges_auth_token_with_extra_headers():
    runtime = RemoteRuntime(
        host="http://127.0.0.1",
        auth_token="test-token",
        extra_headers={"sbx-traffic-access-token": "sandbox-token"},
    )
    assert runtime._headers == {
        "X-API-Key": "test-token",
        "sbx-traffic-access-token": "sandbox-token",
    }
