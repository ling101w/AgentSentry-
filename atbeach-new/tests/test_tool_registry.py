from __future__ import annotations

import copy

import pytest

from agentsentry.tool_registry import (
    ToolRegistryError,
    build_tool_registry,
    classify_observed_tool,
    select_registry_for_catalog,
    validate_tool_registry,
)


def tool(name: str, *, description: str = "", properties: dict | None = None) -> dict:
    return {
        "catalog_index": 0,
        "name": name,
        "description": description,
        "parameters": {"type": "object", "properties": properties or {}},
        "_source": "fixture",
    }


def test_public_business_reads_get_unscoped_read_manifests() -> None:
    for name in (
        "searchLandmarks",
        "getWeatherForecast",
        "getCrimeStatistics",
        "searchLocation",
        "bulkGeolocationLookup",
        "getNearbyAmenities",
        "getUrlSafetyDetails",
    ):
        descriptor = classify_observed_tool(tool(name))
        assert descriptor["canonical_tool"] == "external_api_read"
        assert descriptor["effect"] == "read_only"
        assert descriptor["data_sensitivity"] == "public"
        assert descriptor["manifest"]["requiresExplicitAuthorization"] is False
        assert descriptor["manifest"]["canExfiltrate"] is False


def test_non_verb_public_lookup_with_sort_parameters_stays_low_risk() -> None:
    routing = classify_observed_tool(
        tool(
            "routing",
            description="Find a route between two places.",
            properties={
                "start": {"type": "string"},
                "end": {"type": "string"},
            },
        )
    )
    cities = classify_observed_tool(
        tool(
            "getCitiesByCountry",
            description="Retrieve a list of cities located in a specific country.",
            properties={
                "country": {"type": "string"},
                "order": {"type": "string"},
                "sort": {"type": "string"},
            },
        )
    )

    for descriptor in (routing, cities):
        assert descriptor["canonical_tool"] == "external_api_read"
        assert descriptor["effect"] == "read_only"
        assert descriptor["data_sensitivity"] == "public"
        assert descriptor["manifest"]["acceptsSensitiveData"] is False
        assert descriptor["manifest"]["requiresExplicitAuthorization"] is False


def test_account_token_is_auth_material_not_automatic_exfiltration() -> None:
    descriptor = classify_observed_tool(
        tool(
            "getAccountInformation",
            properties={
                "accessToken": {"type": "string"},
                "accountId": {"type": "string"},
            },
        )
    )

    assert descriptor["canonical_tool"] == "call_api"
    assert descriptor["data_sensitivity"] == "user_private"
    assert descriptor["credential_fields"] == ["accessToken"]
    assert descriptor["manifest"]["requiresExplicitAuthorization"] is True
    assert descriptor["manifest"]["canExfiltrate"] is False


def test_privileged_writes_remain_authorization_gated() -> None:
    add_user = classify_observed_tool(
        tool(
            "addUser",
            properties={
                "email": {"type": "string"},
                "password": {"type": "string"},
                "groupId": {"type": "string"},
            },
        )
    )
    firewall = classify_observed_tool(
        tool(
            "remove_tags_from_firewall",
            properties={"accessToken": {"type": "string"}, "firewallId": {"type": "string"}},
        )
    )

    assert add_user["effect"] == "privileged_change"
    assert add_user["manifest"]["requiresExplicitAuthorization"] is True
    assert firewall["effect"] == "privileged_change"
    assert firewall["manifest"]["requiresExplicitAuthorization"] is True


def test_registry_is_bound_to_exact_catalog_definition_and_hash() -> None:
    catalog = [tool("searchLandmarks", description="Search public landmarks.")]
    registry = build_tool_registry([catalog])
    subset = select_registry_for_catalog(registry, catalog)

    assert subset["registry_sha256"]
    changed = copy.deepcopy(registry)
    changed["tools"][0]["manifest"]["requiresExplicitAuthorization"] = True
    with pytest.raises(ToolRegistryError, match="SHA-256 mismatch"):
        validate_tool_registry(changed)

    changed_catalog = [tool("searchLandmarks", description="Changed definition.")]
    with pytest.raises(ToolRegistryError, match="missing exact tool definition"):
        select_registry_for_catalog(registry, changed_catalog)
