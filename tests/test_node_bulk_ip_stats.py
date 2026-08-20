from uuid import uuid4

import pytest
from PasarGuardNodeBridge import NodeAPIError
from PasarGuardNodeBridge.common import service_pb2 as service

from app.db.models import Admin, Group, ProxyInbound, User, UserStatus, users_groups_association
from app.models.node import UserIPRankingQuery
from app.models.proxy import ProxyTable
from app.operation import OperatorType
from app.operation.node import NodeOperation
from tests.api import TestSession


def _users_response(users: dict[str, dict[str, int]]) -> service.StatsAllOnlineIpListResponse:
    return service.StatsAllOnlineIpListResponse(
        users={email: service.StatsOnlineIpListResponse(name=email, ips=ips) for email, ips in users.items()}
    )


class FakeGrpcClient:
    def __init__(self, response):
        self._response = response

    async def GetUsersOnlineIpListStats(self, request, metadata=None):
        return self._response


class FakeGrpcNode:
    def __init__(self, response):
        self._client = FakeGrpcClient(response)

    async def _handle_grpc_request(self, method, request, timeout=None):
        return await method(request)


class FakeRestNode:
    """REST-transport nodes don't expose _client/_handle_grpc_request."""


@pytest.mark.asyncio
async def test_bulk_ip_list_converts_response_by_user(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)
    response = _users_response({"1": {"1.2.3.4": 1000}, "2": {"5.6.7.8": 2000}})
    fake_node = FakeGrpcNode(response)

    async def fake_get_node(node_id):
        return fake_node

    monkeypatch.setattr("app.operation.node.node_manager.get_node", fake_get_node)

    result = await operation._get_node_users_ip_list_bulk_safe(1)

    assert result == {"1": {"1.2.3.4": 1000}, "2": {"5.6.7.8": 2000}}


@pytest.mark.asyncio
async def test_bulk_ip_list_returns_none_for_rest_transport_node(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)

    async def fake_get_node(node_id):
        return FakeRestNode()

    monkeypatch.setattr("app.operation.node.node_manager.get_node", fake_get_node)

    result = await operation._get_node_users_ip_list_bulk_safe(1)

    assert result is None


@pytest.mark.asyncio
async def test_bulk_ip_list_returns_none_when_node_missing(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)

    async def fake_get_node(node_id):
        return None

    monkeypatch.setattr("app.operation.node.node_manager.get_node", fake_get_node)

    result = await operation._get_node_users_ip_list_bulk_safe(1)

    assert result is None


@pytest.mark.asyncio
async def test_bulk_ip_list_swallows_non_404_node_api_error(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)
    logged = []

    async def fake_get_node(node_id):
        raise NodeAPIError(500, "boom")

    monkeypatch.setattr("app.operation.node.node_manager.get_node", fake_get_node)
    monkeypatch.setattr("app.operation.node.logger.error", lambda msg: logged.append(msg))

    result = await operation._get_node_users_ip_list_bulk_safe(1)

    assert result is None
    assert len(logged) == 1


@pytest.mark.asyncio
async def test_bulk_ip_list_skips_node_predating_rpc_without_logging(monkeypatch: pytest.MonkeyPatch):
    """Old node binaries don't implement GetUsersOnlineIpListStats yet; the
    bridge surfaces that as a 501 NodeAPIError, which should be skipped like
    a 404 rather than logged as an error."""
    operation = NodeOperation(operator_type=OperatorType.API)
    logged = []

    async def fake_get_node(node_id):
        raise NodeAPIError(501, "unimplemented")

    monkeypatch.setattr("app.operation.node.node_manager.get_node", fake_get_node)
    monkeypatch.setattr("app.operation.node.logger.error", lambda msg: logged.append(msg))

    result = await operation._get_node_users_ip_list_bulk_safe(1)

    assert result is None
    assert logged == []


@pytest.mark.asyncio
async def test_online_ips_unions_across_nodes(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)

    per_node = {
        1: {"1": {"1.2.3.4": 1000}, "2": {"9.9.9.9": 500}},
        2: {"1": {"5.6.7.8": 2000}},
    }

    async def fake_get_healthy_nodes():
        return [(1, object()), (2, object())]

    async def fake_bulk(node_id):
        return per_node[node_id]

    monkeypatch.setattr("app.operation.node.node_manager.get_healthy_nodes", fake_get_healthy_nodes)
    monkeypatch.setattr(operation, "_get_node_users_ip_list_bulk_safe", fake_bulk)

    result, skipped_node_count = await operation._get_users_online_ips()

    assert result == {1: {"1.2.3.4": 1000, "5.6.7.8": 2000}, 2: {"9.9.9.9": 500}}
    assert skipped_node_count == 0


@pytest.mark.asyncio
async def test_online_ips_keeps_latest_last_seen_for_same_ip_across_nodes(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)

    per_node = {
        1: {"1": {"1.2.3.4": 1000}},
        2: {"1": {"1.2.3.4": 2000}},
    }

    async def fake_get_healthy_nodes():
        return [(1, object()), (2, object())]

    async def fake_bulk(node_id):
        return per_node[node_id]

    monkeypatch.setattr("app.operation.node.node_manager.get_healthy_nodes", fake_get_healthy_nodes)
    monkeypatch.setattr(operation, "_get_node_users_ip_list_bulk_safe", fake_bulk)

    result, skipped_node_count = await operation._get_users_online_ips()

    assert result == {1: {"1.2.3.4": 2000}}
    assert skipped_node_count == 0


@pytest.mark.asyncio
async def test_online_ips_skips_nodes_that_return_none(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)

    async def fake_get_healthy_nodes():
        return [(1, object()), (2, object())]

    async def fake_bulk(node_id):
        if node_id == 1:
            return {"1": {"1.2.3.4": 1000}}
        return None  # e.g. REST-transport node

    monkeypatch.setattr("app.operation.node.node_manager.get_healthy_nodes", fake_get_healthy_nodes)
    monkeypatch.setattr(operation, "_get_node_users_ip_list_bulk_safe", fake_bulk)

    result, skipped_node_count = await operation._get_users_online_ips()

    assert result == {1: {"1.2.3.4": 1000}}
    assert skipped_node_count == 1


@pytest.mark.asyncio
async def test_online_ips_filters_by_node_ids(monkeypatch: pytest.MonkeyPatch):
    operation = NodeOperation(operator_type=OperatorType.API)

    per_node = {
        1: {"1": {"1.2.3.4": 1000}},
        2: {"1": {"5.6.7.8": 2000}},
    }
    queried = []

    async def fake_get_healthy_nodes():
        return [(1, object()), (2, object())]

    async def fake_bulk(node_id):
        queried.append(node_id)
        return per_node[node_id]

    monkeypatch.setattr("app.operation.node.node_manager.get_healthy_nodes", fake_get_healthy_nodes)
    monkeypatch.setattr(operation, "_get_node_users_ip_list_bulk_safe", fake_bulk)

    result, skipped_node_count = await operation._get_users_online_ips(node_ids=[2])

    assert queried == [2]
    assert result == {1: {"5.6.7.8": 2000}}
    assert skipped_node_count == 0


def _ips(count: int, *, offset: int = 0) -> dict[str, int]:
    """count distinct fake IPs with dummy last-seen timestamps, for ips_by_user fixtures."""
    return {f"10.0.{offset}.{i}": 1000 + i for i in range(count)}


async def _make_ranking_fixture():
    """Two admins, one group, three users with varying status/traffic, for filter tests."""
    suffix = uuid4().hex[:8]
    async with TestSession() as session:
        admin_a = Admin(username=f"ipr_admin_a_{suffix}", hashed_password="secret", role_id=3)
        admin_b = Admin(username=f"ipr_admin_b_{suffix}", hashed_password="secret", role_id=3)
        session.add_all([admin_a, admin_b])
        await session.flush()

        inbound = ProxyInbound(tag=f"ipr_tag_{suffix}")
        group = Group(name=f"ipr_group_{suffix}", inbounds=[inbound])
        session.add(group)
        await session.flush()

        active_user = User(
            username=f"ipr_active_{suffix}",
            admin_id=admin_a.id,
            proxy_settings=ProxyTable().dict(no_obj=True),
            status=UserStatus.active,
            used_traffic=1_000,
        )
        limited_user = User(
            username=f"ipr_limited_{suffix}",
            admin_id=admin_a.id,
            proxy_settings=ProxyTable().dict(no_obj=True),
            status=UserStatus.limited,
            used_traffic=2_000,
        )
        other_admin_user = User(
            username=f"ipr_other_admin_{suffix}",
            admin_id=admin_b.id,
            proxy_settings=ProxyTable().dict(no_obj=True),
            status=UserStatus.active,
            used_traffic=3_000,
        )
        session.add_all([active_user, limited_user, other_admin_user])
        await session.flush()

        await session.execute(
            users_groups_association.insert(),
            [{"user_id": active_user.id, "groups_id": group.id}],
        )
        await session.commit()

        return {
            "admin_a": admin_a.id,
            "admin_b": admin_b.id,
            "group": group.id,
            "active": active_user.id,
            "limited": limited_user.id,
            "other_admin": other_admin_user.id,
        }


@pytest.mark.asyncio
async def test_ip_ranking_filters_by_ip_count_range():
    ids = await _make_ranking_fixture()
    operation = NodeOperation(operator_type=OperatorType.API)
    ips_by_user = {ids["active"]: _ips(10), ids["limited"]: _ips(50), ids["other_admin"]: _ips(100)}

    async with TestSession() as session:
        result = await operation._resolve_ip_ranking(
            session, ips_by_user, None, UserIPRankingQuery(ip_count_min=50, ip_count_max=100)
        )

    assert {entry.user_id for entry in result.users} == {ids["limited"], ids["other_admin"]}


@pytest.mark.asyncio
async def test_ip_ranking_filters_by_admin_ids():
    ids = await _make_ranking_fixture()
    operation = NodeOperation(operator_type=OperatorType.API)
    ips_by_user = {ids["active"]: _ips(5), ids["limited"]: _ips(5), ids["other_admin"]: _ips(5)}

    async with TestSession() as session:
        result = await operation._resolve_ip_ranking(
            session, ips_by_user, None, UserIPRankingQuery(admin_ids=[ids["admin_a"]])
        )

    assert {entry.user_id for entry in result.users} == {ids["active"], ids["limited"]}


@pytest.mark.asyncio
async def test_ip_ranking_filters_by_group_ids():
    ids = await _make_ranking_fixture()
    operation = NodeOperation(operator_type=OperatorType.API)
    ips_by_user = {ids["active"]: _ips(5), ids["limited"]: _ips(5), ids["other_admin"]: _ips(5)}

    async with TestSession() as session:
        result = await operation._resolve_ip_ranking(
            session, ips_by_user, None, UserIPRankingQuery(group_ids=[ids["group"]])
        )

    assert {entry.user_id for entry in result.users} == {ids["active"]}


@pytest.mark.asyncio
async def test_ip_ranking_filters_by_status():
    ids = await _make_ranking_fixture()
    operation = NodeOperation(operator_type=OperatorType.API)
    ips_by_user = {ids["active"]: _ips(5), ids["limited"]: _ips(5), ids["other_admin"]: _ips(5)}

    async with TestSession() as session:
        result = await operation._resolve_ip_ranking(
            session, ips_by_user, None, UserIPRankingQuery(status=UserStatus.limited)
        )

    assert {entry.user_id for entry in result.users} == {ids["limited"]}


@pytest.mark.asyncio
async def test_ip_ranking_applies_offset_and_limit_after_sorting():
    ids = await _make_ranking_fixture()
    operation = NodeOperation(operator_type=OperatorType.API)
    ips_by_user = {ids["active"]: _ips(10), ids["limited"]: _ips(30), ids["other_admin"]: _ips(20)}

    async with TestSession() as session:
        result = await operation._resolve_ip_ranking(session, ips_by_user, None, UserIPRankingQuery(offset=1, limit=1))

    # sorted desc by count: limited(30), other_admin(20), active(10) -> offset 1, limit 1 -> other_admin
    assert [entry.user_id for entry in result.users] == [ids["other_admin"]]
    assert result.total == 3


@pytest.mark.asyncio
async def test_ip_ranking_entries_include_ips_and_traffic():
    ids = await _make_ranking_fixture()
    operation = NodeOperation(operator_type=OperatorType.API)
    active_ips = _ips(2)
    ips_by_user = {ids["active"]: active_ips, ids["limited"]: _ips(1)}

    async with TestSession() as session:
        result = await operation._resolve_ip_ranking(session, ips_by_user, None, UserIPRankingQuery())

    entry = next(entry for entry in result.users if entry.user_id == ids["active"])
    assert entry.ips == active_ips
    assert entry.distinct_ip_count == 2
    assert entry.used_traffic == 1_000  # set on active_user in _make_ranking_fixture
