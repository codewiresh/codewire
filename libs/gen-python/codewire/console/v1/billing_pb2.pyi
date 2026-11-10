import datetime

from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ListOrgPlansRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListOrgPlansResponse(_message.Message):
    __slots__ = ("plans",)
    class PlansEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: OrgPlan
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[OrgPlan, _Mapping]] = ...) -> None: ...
    PLANS_FIELD_NUMBER: _ClassVar[int]
    plans: _containers.MessageMap[str, OrgPlan]
    def __init__(self, plans: _Optional[_Mapping[str, OrgPlan]] = ...) -> None: ...

class OrgPlan(_message.Message):
    __slots__ = ("display_name", "price_cents", "included_devs", "max_concurrent_ws", "max_team_members", "storage_gb", "is_contact_us", "archived")
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    PRICE_CENTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_DEVS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENT_WS_FIELD_NUMBER: _ClassVar[int]
    MAX_TEAM_MEMBERS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_GB_FIELD_NUMBER: _ClassVar[int]
    IS_CONTACT_US_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    display_name: str
    price_cents: int
    included_devs: int
    max_concurrent_ws: int
    max_team_members: int
    storage_gb: int
    is_contact_us: bool
    archived: bool
    def __init__(self, display_name: _Optional[str] = ..., price_cents: _Optional[int] = ..., included_devs: _Optional[int] = ..., max_concurrent_ws: _Optional[int] = ..., max_team_members: _Optional[int] = ..., storage_gb: _Optional[int] = ..., is_contact_us: _Optional[bool] = ..., archived: _Optional[bool] = ...) -> None: ...

class ListResourcePlansRequest(_message.Message):
    __slots__ = ("resource_type",)
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    resource_type: str
    def __init__(self, resource_type: _Optional[str] = ...) -> None: ...

class ListResourcePlansResponse(_message.Message):
    __slots__ = ("plans",)
    class PlansEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ResourcePlan
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ResourcePlan, _Mapping]] = ...) -> None: ...
    PLANS_FIELD_NUMBER: _ClassVar[int]
    plans: _containers.MessageMap[str, ResourcePlan]
    def __init__(self, plans: _Optional[_Mapping[str, ResourcePlan]] = ...) -> None: ...

class ResourcePlan(_message.Message):
    __slots__ = ("display_name", "price_cents", "included_devs", "max_concurrent_ws", "max_team_members", "storage_gb", "is_contact_us", "is_admin_only", "archived", "included_cpu_hours", "included_mem_gb_hours", "included_disk_gb_hours", "cpu_overage_millicents", "mem_overage_millicents", "disk_overage_millicents")
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    PRICE_CENTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_DEVS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENT_WS_FIELD_NUMBER: _ClassVar[int]
    MAX_TEAM_MEMBERS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_GB_FIELD_NUMBER: _ClassVar[int]
    IS_CONTACT_US_FIELD_NUMBER: _ClassVar[int]
    IS_ADMIN_ONLY_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_MEM_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_DISK_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    CPU_OVERAGE_MILLICENTS_FIELD_NUMBER: _ClassVar[int]
    MEM_OVERAGE_MILLICENTS_FIELD_NUMBER: _ClassVar[int]
    DISK_OVERAGE_MILLICENTS_FIELD_NUMBER: _ClassVar[int]
    display_name: str
    price_cents: int
    included_devs: int
    max_concurrent_ws: int
    max_team_members: int
    storage_gb: int
    is_contact_us: bool
    is_admin_only: bool
    archived: bool
    included_cpu_hours: int
    included_mem_gb_hours: int
    included_disk_gb_hours: int
    cpu_overage_millicents: int
    mem_overage_millicents: int
    disk_overage_millicents: int
    def __init__(self, display_name: _Optional[str] = ..., price_cents: _Optional[int] = ..., included_devs: _Optional[int] = ..., max_concurrent_ws: _Optional[int] = ..., max_team_members: _Optional[int] = ..., storage_gb: _Optional[int] = ..., is_contact_us: _Optional[bool] = ..., is_admin_only: _Optional[bool] = ..., archived: _Optional[bool] = ..., included_cpu_hours: _Optional[int] = ..., included_mem_gb_hours: _Optional[int] = ..., included_disk_gb_hours: _Optional[int] = ..., cpu_overage_millicents: _Optional[int] = ..., mem_overage_millicents: _Optional[int] = ..., disk_overage_millicents: _Optional[int] = ...) -> None: ...

class GetSignupCreditRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetSignupCreditResponse(_message.Message):
    __slots__ = ("amount_nano_eur",)
    AMOUNT_NANO_EUR_FIELD_NUMBER: _ClassVar[int]
    amount_nano_eur: int
    def __init__(self, amount_nano_eur: _Optional[int] = ...) -> None: ...

class GetBillingOverviewRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class GetBillingOverviewResponse(_message.Message):
    __slots__ = ("billing_enabled", "has_payment_method", "plan", "plan_display_name", "status", "trial_end", "trial_days", "seat_count", "included_devs", "extra_seat_price_cents", "limits", "current_period_end", "active_subscriptions", "total_monthly_cost_cents", "current_month_usage", "credit_balance_nano_eur", "rates", "unmetered", "auto_top_up_enabled", "auto_top_up_cents", "credit_exhausted_at", "month_usage_nano_eur")
    BILLING_ENABLED_FIELD_NUMBER: _ClassVar[int]
    HAS_PAYMENT_METHOD_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    PLAN_DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TRIAL_END_FIELD_NUMBER: _ClassVar[int]
    TRIAL_DAYS_FIELD_NUMBER: _ClassVar[int]
    SEAT_COUNT_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_DEVS_FIELD_NUMBER: _ClassVar[int]
    EXTRA_SEAT_PRICE_CENTS_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_PERIOD_END_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_SUBSCRIPTIONS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_MONTHLY_COST_CENTS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_MONTH_USAGE_FIELD_NUMBER: _ClassVar[int]
    CREDIT_BALANCE_NANO_EUR_FIELD_NUMBER: _ClassVar[int]
    RATES_FIELD_NUMBER: _ClassVar[int]
    UNMETERED_FIELD_NUMBER: _ClassVar[int]
    AUTO_TOP_UP_ENABLED_FIELD_NUMBER: _ClassVar[int]
    AUTO_TOP_UP_CENTS_FIELD_NUMBER: _ClassVar[int]
    CREDIT_EXHAUSTED_AT_FIELD_NUMBER: _ClassVar[int]
    MONTH_USAGE_NANO_EUR_FIELD_NUMBER: _ClassVar[int]
    billing_enabled: bool
    has_payment_method: bool
    plan: str
    plan_display_name: str
    status: str
    trial_end: _timestamp_pb2.Timestamp
    trial_days: int
    seat_count: int
    included_devs: int
    extra_seat_price_cents: int
    limits: BillingLimits
    current_period_end: _timestamp_pb2.Timestamp
    active_subscriptions: int
    total_monthly_cost_cents: int
    current_month_usage: UsageSummary
    credit_balance_nano_eur: int
    rates: CreditRates
    unmetered: bool
    auto_top_up_enabled: bool
    auto_top_up_cents: int
    credit_exhausted_at: _timestamp_pb2.Timestamp
    month_usage_nano_eur: int
    def __init__(self, billing_enabled: _Optional[bool] = ..., has_payment_method: _Optional[bool] = ..., plan: _Optional[str] = ..., plan_display_name: _Optional[str] = ..., status: _Optional[str] = ..., trial_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., trial_days: _Optional[int] = ..., seat_count: _Optional[int] = ..., included_devs: _Optional[int] = ..., extra_seat_price_cents: _Optional[int] = ..., limits: _Optional[_Union[BillingLimits, _Mapping]] = ..., current_period_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., active_subscriptions: _Optional[int] = ..., total_monthly_cost_cents: _Optional[int] = ..., current_month_usage: _Optional[_Union[UsageSummary, _Mapping]] = ..., credit_balance_nano_eur: _Optional[int] = ..., rates: _Optional[_Union[CreditRates, _Mapping]] = ..., unmetered: _Optional[bool] = ..., auto_top_up_enabled: _Optional[bool] = ..., auto_top_up_cents: _Optional[int] = ..., credit_exhausted_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., month_usage_nano_eur: _Optional[int] = ...) -> None: ...

class CreditRates(_message.Message):
    __slots__ = ("cpu_nano_eur_per_vcpu_hour", "memory_nano_eur_per_gib_hour", "disk_nano_eur_per_gib_hour")
    CPU_NANO_EUR_PER_VCPU_HOUR_FIELD_NUMBER: _ClassVar[int]
    MEMORY_NANO_EUR_PER_GIB_HOUR_FIELD_NUMBER: _ClassVar[int]
    DISK_NANO_EUR_PER_GIB_HOUR_FIELD_NUMBER: _ClassVar[int]
    cpu_nano_eur_per_vcpu_hour: int
    memory_nano_eur_per_gib_hour: int
    disk_nano_eur_per_gib_hour: int
    def __init__(self, cpu_nano_eur_per_vcpu_hour: _Optional[int] = ..., memory_nano_eur_per_gib_hour: _Optional[int] = ..., disk_nano_eur_per_gib_hour: _Optional[int] = ...) -> None: ...

class UpdateAutoTopUpRequest(_message.Message):
    __slots__ = ("org_id", "enabled", "amount_cents")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    enabled: bool
    amount_cents: int
    def __init__(self, org_id: _Optional[str] = ..., enabled: _Optional[bool] = ..., amount_cents: _Optional[int] = ...) -> None: ...

class UpdateAutoTopUpResponse(_message.Message):
    __slots__ = ("enabled", "amount_cents")
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    amount_cents: int
    def __init__(self, enabled: _Optional[bool] = ..., amount_cents: _Optional[int] = ...) -> None: ...

class BillingLimitUsage(_message.Message):
    __slots__ = ("used", "max")
    USED_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    used: int
    max: int
    def __init__(self, used: _Optional[int] = ..., max: _Optional[int] = ...) -> None: ...

class BillingLimits(_message.Message):
    __slots__ = ("team_members", "concurrent_workspaces", "storage_gb")
    TEAM_MEMBERS_FIELD_NUMBER: _ClassVar[int]
    CONCURRENT_WORKSPACES_FIELD_NUMBER: _ClassVar[int]
    STORAGE_GB_FIELD_NUMBER: _ClassVar[int]
    team_members: BillingLimitUsage
    concurrent_workspaces: int
    storage_gb: int
    def __init__(self, team_members: _Optional[_Union[BillingLimitUsage, _Mapping]] = ..., concurrent_workspaces: _Optional[int] = ..., storage_gb: _Optional[int] = ...) -> None: ...

class UsageSummary(_message.Message):
    __slots__ = ("cpu_hours", "memory_gb_hours", "storage_gb_hours")
    CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    cpu_hours: float
    memory_gb_hours: float
    storage_gb_hours: float
    def __init__(self, cpu_hours: _Optional[float] = ..., memory_gb_hours: _Optional[float] = ..., storage_gb_hours: _Optional[float] = ...) -> None: ...

class ListInvoicesRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class ListInvoicesResponse(_message.Message):
    __slots__ = ("invoices",)
    INVOICES_FIELD_NUMBER: _ClassVar[int]
    invoices: _containers.RepeatedCompositeFieldContainer[Invoice]
    def __init__(self, invoices: _Optional[_Iterable[_Union[Invoice, _Mapping]]] = ...) -> None: ...

class Invoice(_message.Message):
    __slots__ = ("id", "stripe_invoice_id", "status", "amount_due", "amount_paid", "currency", "hosted_invoice_url", "invoice_pdf", "period_start", "period_end", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    STRIPE_INVOICE_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_DUE_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_PAID_FIELD_NUMBER: _ClassVar[int]
    CURRENCY_FIELD_NUMBER: _ClassVar[int]
    HOSTED_INVOICE_URL_FIELD_NUMBER: _ClassVar[int]
    INVOICE_PDF_FIELD_NUMBER: _ClassVar[int]
    PERIOD_START_FIELD_NUMBER: _ClassVar[int]
    PERIOD_END_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    stripe_invoice_id: str
    status: str
    amount_due: int
    amount_paid: int
    currency: str
    hosted_invoice_url: str
    invoice_pdf: str
    period_start: _timestamp_pb2.Timestamp
    period_end: _timestamp_pb2.Timestamp
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., stripe_invoice_id: _Optional[str] = ..., status: _Optional[str] = ..., amount_due: _Optional[int] = ..., amount_paid: _Optional[int] = ..., currency: _Optional[str] = ..., hosted_invoice_url: _Optional[str] = ..., invoice_pdf: _Optional[str] = ..., period_start: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., period_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListBillingEventsRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class ListBillingEventsResponse(_message.Message):
    __slots__ = ("events",)
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    events: _containers.RepeatedCompositeFieldContainer[BillingEvent]
    def __init__(self, events: _Optional[_Iterable[_Union[BillingEvent, _Mapping]]] = ...) -> None: ...

class BillingEvent(_message.Message):
    __slots__ = ("id", "event_type", "org_id", "amount_cents", "currency", "stripe_item_id", "metadata", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]
    CURRENCY_FIELD_NUMBER: _ClassVar[int]
    STRIPE_ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: int
    event_type: str
    org_id: str
    amount_cents: int
    currency: str
    stripe_item_id: str
    metadata: _struct_pb2.Struct
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[int] = ..., event_type: _Optional[str] = ..., org_id: _Optional[str] = ..., amount_cents: _Optional[int] = ..., currency: _Optional[str] = ..., stripe_item_id: _Optional[str] = ..., metadata: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class GetEnvironmentUsageRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentUsageResponse(_message.Message):
    __slots__ = ("current_month", "hourly_breakdown", "per_environment")
    CURRENT_MONTH_FIELD_NUMBER: _ClassVar[int]
    HOURLY_BREAKDOWN_FIELD_NUMBER: _ClassVar[int]
    PER_ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    current_month: EnvironmentUsageMonth
    hourly_breakdown: _containers.RepeatedCompositeFieldContainer[EnvironmentUsageHour]
    per_environment: _containers.RepeatedCompositeFieldContainer[EnvironmentUsageEntry]
    def __init__(self, current_month: _Optional[_Union[EnvironmentUsageMonth, _Mapping]] = ..., hourly_breakdown: _Optional[_Iterable[_Union[EnvironmentUsageHour, _Mapping]]] = ..., per_environment: _Optional[_Iterable[_Union[EnvironmentUsageEntry, _Mapping]]] = ...) -> None: ...

class EnvironmentUsageMonth(_message.Message):
    __slots__ = ("cpu_hours", "mem_gb_hours", "disk_gb_hours", "cost_cents", "included_cpu_hours", "included_mem_gb_hours")
    CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    MEM_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    DISK_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    COST_CENTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_MEM_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    cpu_hours: float
    mem_gb_hours: float
    disk_gb_hours: float
    cost_cents: int
    included_cpu_hours: int
    included_mem_gb_hours: int
    def __init__(self, cpu_hours: _Optional[float] = ..., mem_gb_hours: _Optional[float] = ..., disk_gb_hours: _Optional[float] = ..., cost_cents: _Optional[int] = ..., included_cpu_hours: _Optional[int] = ..., included_mem_gb_hours: _Optional[int] = ...) -> None: ...

class EnvironmentUsageHour(_message.Message):
    __slots__ = ("hour", "cpu_hours", "mem_gb_hours", "cost_cents")
    HOUR_FIELD_NUMBER: _ClassVar[int]
    CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    MEM_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    COST_CENTS_FIELD_NUMBER: _ClassVar[int]
    hour: _timestamp_pb2.Timestamp
    cpu_hours: float
    mem_gb_hours: float
    cost_cents: int
    def __init__(self, hour: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., cpu_hours: _Optional[float] = ..., mem_gb_hours: _Optional[float] = ..., cost_cents: _Optional[int] = ...) -> None: ...

class EnvironmentUsageEntry(_message.Message):
    __slots__ = ("id", "name", "running_seconds", "cost_cents", "cpu_millicores", "memory_mb", "hourly_cents")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RUNNING_SECONDS_FIELD_NUMBER: _ClassVar[int]
    COST_CENTS_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    HOURLY_CENTS_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    running_seconds: int
    cost_cents: int
    cpu_millicores: int
    memory_mb: int
    hourly_cents: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., running_seconds: _Optional[int] = ..., cost_cents: _Optional[int] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., hourly_cents: _Optional[int] = ...) -> None: ...

class CreateCheckoutSessionRequest(_message.Message):
    __slots__ = ("org_id", "plan", "success_url", "cancel_url")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_URL_FIELD_NUMBER: _ClassVar[int]
    CANCEL_URL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    plan: str
    success_url: str
    cancel_url: str
    def __init__(self, org_id: _Optional[str] = ..., plan: _Optional[str] = ..., success_url: _Optional[str] = ..., cancel_url: _Optional[str] = ...) -> None: ...

class CreateCheckoutSessionResponse(_message.Message):
    __slots__ = ("checkout_url",)
    CHECKOUT_URL_FIELD_NUMBER: _ClassVar[int]
    checkout_url: str
    def __init__(self, checkout_url: _Optional[str] = ...) -> None: ...

class CreatePortalSessionRequest(_message.Message):
    __slots__ = ("org_id", "return_url")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    RETURN_URL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    return_url: str
    def __init__(self, org_id: _Optional[str] = ..., return_url: _Optional[str] = ...) -> None: ...

class CreatePortalSessionResponse(_message.Message):
    __slots__ = ("portal_url",)
    PORTAL_URL_FIELD_NUMBER: _ClassVar[int]
    portal_url: str
    def __init__(self, portal_url: _Optional[str] = ...) -> None: ...

class CreateSetupSessionRequest(_message.Message):
    __slots__ = ("org_id", "success_url", "cancel_url")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_URL_FIELD_NUMBER: _ClassVar[int]
    CANCEL_URL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    success_url: str
    cancel_url: str
    def __init__(self, org_id: _Optional[str] = ..., success_url: _Optional[str] = ..., cancel_url: _Optional[str] = ...) -> None: ...

class CreateSetupSessionResponse(_message.Message):
    __slots__ = ("checkout_url",)
    CHECKOUT_URL_FIELD_NUMBER: _ClassVar[int]
    checkout_url: str
    def __init__(self, checkout_url: _Optional[str] = ...) -> None: ...
