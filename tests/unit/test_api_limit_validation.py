import pytest

@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/v1/audit",
        "/api/v1/pr-health",
        "/api/v1/contributors",
        "/api/v1/stale-log",
    ],
)
@pytest.mark.parametrize("limit", [-1, 0])
def test_list_endpoints_reject_non_positive_limits(
    client, endpoint, limit
):
    response = client.get(endpoint, params={"limit": limit})
    assert response.status_code == 422
