import datetime

from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetCatalogRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetCatalogResponse(_message.Message):
    __slots__ = ("plans", "prices", "settings")
    PLANS_FIELD_NUMBER: _ClassVar[int]
    PRICES_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    plans: _containers.RepeatedCompositeFieldContainer[CatalogPlan]
    prices: _containers.RepeatedCompositeFieldContainer[CatalogPrice]
    settings: _containers.RepeatedCompositeFieldContainer[CatalogSetting]
    def __init__(self, plans: _Optional[_Iterable[_Union[CatalogPlan, _Mapping]]] = ..., prices: _Optional[_Iterable[_Union[CatalogPrice, _Mapping]]] = ..., settings: _Optional[_Iterable[_Union[CatalogSetting, _Mapping]]] = ...) -> None: ...

class PlanSpec(_message.Message):
    __slots__ = ("display_name", "price_cents", "included_devs", "max_concurrent_ws", "max_team_members", "storage_gb", "is_contact_us", "is_admin_only", "included_cpu_hours", "included_mem_gb_hours", "included_disk_gb_hours", "cpu_overage_cents", "mem_overage_cents", "disk_overage_cents")
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    PRICE_CENTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_DEVS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENT_WS_FIELD_NUMBER: _ClassVar[int]
    MAX_TEAM_MEMBERS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_GB_FIELD_NUMBER: _ClassVar[int]
    IS_CONTACT_US_FIELD_NUMBER: _ClassVar[int]
    IS_ADMIN_ONLY_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_MEM_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_DISK_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    CPU_OVERAGE_CENTS_FIELD_NUMBER: _ClassVar[int]
    MEM_OVERAGE_CENTS_FIELD_NUMBER: _ClassVar[int]
    DISK_OVERAGE_CENTS_FIELD_NUMBER: _ClassVar[int]
    display_name: str
    price_cents: int
    included_devs: int
    max_concurrent_ws: int
    max_team_members: int
    storage_gb: int
    is_contact_us: bool
    is_admin_only: bool
    included_cpu_hours: int
    included_mem_gb_hours: int
    included_disk_gb_hours: int
    cpu_overage_cents: float
    mem_overage_cents: float
    disk_overage_cents: float
    def __init__(self, display_name: _Optional[str] = ..., price_cents: _Optional[int] = ..., included_devs: _Optional[int] = ..., max_concurrent_ws: _Optional[int] = ..., max_team_members: _Optional[int] = ..., storage_gb: _Optional[int] = ..., is_contact_us: _Optional[bool] = ..., is_admin_only: _Optional[bool] = ..., included_cpu_hours: _Optional[int] = ..., included_mem_gb_hours: _Optional[int] = ..., included_disk_gb_hours: _Optional[int] = ..., cpu_overage_cents: _Optional[float] = ..., mem_overage_cents: _Optional[float] = ..., disk_overage_cents: _Optional[float] = ...) -> None: ...

class CatalogPlan(_message.Message):
    __slots__ = ("resource_type", "plan_key", "plan", "archived")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    plan: PlanSpec
    archived: bool
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., plan: _Optional[_Union[PlanSpec, _Mapping]] = ..., archived: _Optional[bool] = ...) -> None: ...

class CatalogPrice(_message.Message):
    __slots__ = ("resource_type", "plan_key", "stripe_mode", "price_kind", "stripe_price_id", "archived")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    STRIPE_MODE_FIELD_NUMBER: _ClassVar[int]
    PRICE_KIND_FIELD_NUMBER: _ClassVar[int]
    STRIPE_PRICE_ID_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    stripe_mode: str
    price_kind: str
    stripe_price_id: str
    archived: bool
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., stripe_mode: _Optional[str] = ..., price_kind: _Optional[str] = ..., stripe_price_id: _Optional[str] = ..., archived: _Optional[bool] = ...) -> None: ...

class CatalogSetting(_message.Message):
    __slots__ = ("setting_key", "int_value")
    SETTING_KEY_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    setting_key: str
    int_value: int
    def __init__(self, setting_key: _Optional[str] = ..., int_value: _Optional[int] = ...) -> None: ...

class CreatePlanRequest(_message.Message):
    __slots__ = ("resource_type", "plan_key", "plan")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    plan: PlanSpec
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., plan: _Optional[_Union[PlanSpec, _Mapping]] = ...) -> None: ...

class CreatePlanResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class UpdatePlanRequest(_message.Message):
    __slots__ = ("resource_type", "plan_key", "plan")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    plan: PlanSpec
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., plan: _Optional[_Union[PlanSpec, _Mapping]] = ...) -> None: ...

class UpdatePlanResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SetPlanArchivedRequest(_message.Message):
    __slots__ = ("resource_type", "plan_key", "archived")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    archived: bool
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., archived: _Optional[bool] = ...) -> None: ...

class SetPlanArchivedResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CreatePriceRequest(_message.Message):
    __slots__ = ("resource_type", "plan_key", "stripe_mode", "price_kind", "stripe_price_id")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    STRIPE_MODE_FIELD_NUMBER: _ClassVar[int]
    PRICE_KIND_FIELD_NUMBER: _ClassVar[int]
    STRIPE_PRICE_ID_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    stripe_mode: str
    price_kind: str
    stripe_price_id: str
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., stripe_mode: _Optional[str] = ..., price_kind: _Optional[str] = ..., stripe_price_id: _Optional[str] = ...) -> None: ...

class CreatePriceResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class UpdatePriceRequest(_message.Message):
    __slots__ = ("resource_type", "plan_key", "stripe_mode", "price_kind", "stripe_price_id")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    STRIPE_MODE_FIELD_NUMBER: _ClassVar[int]
    PRICE_KIND_FIELD_NUMBER: _ClassVar[int]
    STRIPE_PRICE_ID_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    stripe_mode: str
    price_kind: str
    stripe_price_id: str
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., stripe_mode: _Optional[str] = ..., price_kind: _Optional[str] = ..., stripe_price_id: _Optional[str] = ...) -> None: ...

class UpdatePriceResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SetPriceArchivedRequest(_message.Message):
    __slots__ = ("resource_type", "plan_key", "stripe_mode", "price_kind", "archived")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    STRIPE_MODE_FIELD_NUMBER: _ClassVar[int]
    PRICE_KIND_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    plan_key: str
    stripe_mode: str
    price_kind: str
    archived: bool
    def __init__(self, resource_type: _Optional[str] = ..., plan_key: _Optional[str] = ..., stripe_mode: _Optional[str] = ..., price_kind: _Optional[str] = ..., archived: _Optional[bool] = ...) -> None: ...

class SetPriceArchivedResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class UpdateSettingRequest(_message.Message):
    __slots__ = ("setting_key", "int_value")
    SETTING_KEY_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    setting_key: str
    int_value: int
    def __init__(self, setting_key: _Optional[str] = ..., int_value: _Optional[int] = ...) -> None: ...

class UpdateSettingResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PreviewSubscriptionMigrationRequest(_message.Message):
    __slots__ = ("resource_type", "source_plan_key", "target_plan_key", "sample_limit")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    TARGET_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    source_plan_key: str
    target_plan_key: str
    sample_limit: int
    def __init__(self, resource_type: _Optional[str] = ..., source_plan_key: _Optional[str] = ..., target_plan_key: _Optional[str] = ..., sample_limit: _Optional[int] = ...) -> None: ...

class MigrationSample(_message.Message):
    __slots__ = ("scope", "org_id", "org_slug", "stripe_subscription_id", "status", "current_plan_key", "current_stripe_price_id")
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_SLUG_FIELD_NUMBER: _ClassVar[int]
    STRIPE_SUBSCRIPTION_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    CURRENT_STRIPE_PRICE_ID_FIELD_NUMBER: _ClassVar[int]
    scope: str
    org_id: str
    org_slug: str
    stripe_subscription_id: str
    status: str
    current_plan_key: str
    current_stripe_price_id: str
    def __init__(self, scope: _Optional[str] = ..., org_id: _Optional[str] = ..., org_slug: _Optional[str] = ..., stripe_subscription_id: _Optional[str] = ..., status: _Optional[str] = ..., current_plan_key: _Optional[str] = ..., current_stripe_price_id: _Optional[str] = ...) -> None: ...

class PreviewSubscriptionMigrationResponse(_message.Message):
    __slots__ = ("resource_type", "source_plan_key", "target_plan_key", "target_stripe_price_id", "matching_count", "candidate_count", "already_on_target", "samples")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    TARGET_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    TARGET_STRIPE_PRICE_ID_FIELD_NUMBER: _ClassVar[int]
    MATCHING_COUNT_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_COUNT_FIELD_NUMBER: _ClassVar[int]
    ALREADY_ON_TARGET_FIELD_NUMBER: _ClassVar[int]
    SAMPLES_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    source_plan_key: str
    target_plan_key: str
    target_stripe_price_id: str
    matching_count: int
    candidate_count: int
    already_on_target: int
    samples: _containers.RepeatedCompositeFieldContainer[MigrationSample]
    def __init__(self, resource_type: _Optional[str] = ..., source_plan_key: _Optional[str] = ..., target_plan_key: _Optional[str] = ..., target_stripe_price_id: _Optional[str] = ..., matching_count: _Optional[int] = ..., candidate_count: _Optional[int] = ..., already_on_target: _Optional[int] = ..., samples: _Optional[_Iterable[_Union[MigrationSample, _Mapping]]] = ...) -> None: ...

class RunSubscriptionMigrationRequest(_message.Message):
    __slots__ = ("resource_type", "source_plan_key", "target_plan_key", "proration_behavior")
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    TARGET_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    PRORATION_BEHAVIOR_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    source_plan_key: str
    target_plan_key: str
    proration_behavior: str
    def __init__(self, resource_type: _Optional[str] = ..., source_plan_key: _Optional[str] = ..., target_plan_key: _Optional[str] = ..., proration_behavior: _Optional[str] = ...) -> None: ...

class MigrationRun(_message.Message):
    __slots__ = ("id", "resource_type", "source_plan_key", "target_plan_key", "target_stripe_price_id", "proration_behavior", "migrated_count", "skipped_count", "failed_count", "created_by", "created_at", "metadata")
    ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    TARGET_PLAN_KEY_FIELD_NUMBER: _ClassVar[int]
    TARGET_STRIPE_PRICE_ID_FIELD_NUMBER: _ClassVar[int]
    PRORATION_BEHAVIOR_FIELD_NUMBER: _ClassVar[int]
    MIGRATED_COUNT_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_COUNT_FIELD_NUMBER: _ClassVar[int]
    FAILED_COUNT_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    id: str
    resource_type: str
    source_plan_key: str
    target_plan_key: str
    target_stripe_price_id: str
    proration_behavior: str
    migrated_count: int
    skipped_count: int
    failed_count: int
    created_by: str
    created_at: _timestamp_pb2.Timestamp
    metadata: _struct_pb2.Struct
    def __init__(self, id: _Optional[str] = ..., resource_type: _Optional[str] = ..., source_plan_key: _Optional[str] = ..., target_plan_key: _Optional[str] = ..., target_stripe_price_id: _Optional[str] = ..., proration_behavior: _Optional[str] = ..., migrated_count: _Optional[int] = ..., skipped_count: _Optional[int] = ..., failed_count: _Optional[int] = ..., created_by: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., metadata: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class RunSubscriptionMigrationResponse(_message.Message):
    __slots__ = ("migration",)
    MIGRATION_FIELD_NUMBER: _ClassVar[int]
    migration: MigrationRun
    def __init__(self, migration: _Optional[_Union[MigrationRun, _Mapping]] = ...) -> None: ...

class ListSubscriptionMigrationsRequest(_message.Message):
    __slots__ = ("limit",)
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    limit: int
    def __init__(self, limit: _Optional[int] = ...) -> None: ...

class ListSubscriptionMigrationsResponse(_message.Message):
    __slots__ = ("migrations",)
    MIGRATIONS_FIELD_NUMBER: _ClassVar[int]
    migrations: _containers.RepeatedCompositeFieldContainer[MigrationRun]
    def __init__(self, migrations: _Optional[_Iterable[_Union[MigrationRun, _Mapping]]] = ...) -> None: ...

class SetOrganizationBillingExemptionRequest(_message.Message):
    __slots__ = ("organization_id", "billing_exempt")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_EXEMPT_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    billing_exempt: bool
    def __init__(self, organization_id: _Optional[str] = ..., billing_exempt: _Optional[bool] = ...) -> None: ...

class SetOrganizationBillingExemptionResponse(_message.Message):
    __slots__ = ("organization_id", "billing_exempt")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_EXEMPT_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    billing_exempt: bool
    def __init__(self, organization_id: _Optional[str] = ..., billing_exempt: _Optional[bool] = ...) -> None: ...

class ListConfidentialOrganizationsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ConfidentialOrganization(_message.Message):
    __slots__ = ("organization_id", "slug", "name")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    slug: str
    name: str
    def __init__(self, organization_id: _Optional[str] = ..., slug: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class ListConfidentialOrganizationsResponse(_message.Message):
    __slots__ = ("organizations",)
    ORGANIZATIONS_FIELD_NUMBER: _ClassVar[int]
    organizations: _containers.RepeatedCompositeFieldContainer[ConfidentialOrganization]
    def __init__(self, organizations: _Optional[_Iterable[_Union[ConfidentialOrganization, _Mapping]]] = ...) -> None: ...

class SetOrganizationConfidentialEnvironmentsRequest(_message.Message):
    __slots__ = ("organization_slug", "enabled")
    ORGANIZATION_SLUG_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    organization_slug: str
    enabled: bool
    def __init__(self, organization_slug: _Optional[str] = ..., enabled: _Optional[bool] = ...) -> None: ...

class SetOrganizationConfidentialEnvironmentsResponse(_message.Message):
    __slots__ = ("organization", "enabled")
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    organization: ConfidentialOrganization
    enabled: bool
    def __init__(self, organization: _Optional[_Union[ConfidentialOrganization, _Mapping]] = ..., enabled: _Optional[bool] = ...) -> None: ...
