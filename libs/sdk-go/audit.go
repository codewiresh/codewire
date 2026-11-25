package codewire

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Every enum in an audit event is its proto value name without the enum's
// prefix, in lower case: "access", "ssh", "out_of_credit", "failed_closed".
// The unspecified value is "", and a value this SDK does not know yet is
// "unknown"; neither fails a read.

// ListAuditEventsOptions selects one environment's events. Name the
// environment by exactly one of EnvironmentID or EnvironmentName; only an ID
// names a deleted one.
type ListAuditEventsOptions struct {
	EnvironmentID   string
	EnvironmentName string
	// Kinds are "access", "lifecycle", "policy", "refused" or "credentials";
	// none means every kind.
	Kinds []string
	// Since is the earliest start, at most 90 days ago; zero is 7 days ago.
	Since time.Time
	// Until is the latest start, exclusive; zero is now.
	Until time.Time
	// Limit is at most this many events; 0 is 100, more than 1,000 is refused.
	Limit uint32
	// Cursor continues from a previous page's NextCursor.
	Cursor string
	// GroupBySubject answers one event per kind and subject for the whole
	// range, with no cursor.
	GroupBySubject bool
}

// AuditEventPage is one page of an environment's events, newest first.
type AuditEventPage struct {
	Environment AuditEnvironment `json:"environment"`
	// Policy is the selected network policy at its current revision; nil
	// when the environment selects none.
	Policy *AuditPolicyRevision `json:"policy,omitempty"`
	Events []AuditEvent         `json:"events"`
	// NextCursor is empty when nothing is older.
	NextCursor string `json:"next_cursor"`
	// LeftOut counts a grouped answer's subjects past its 1,000, and those an
	// hour's overflow event counted.
	LeftOut uint64 `json:"left_out"`
}

type AuditEnvironment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

type AuditPolicyRevision struct {
	Name     string `json:"name"`
	Revision uint32 `json:"revision"`
}

// AuditEvent is one event: exactly one of Access, Lifecycle, Policy,
// Refused, RefusedOverflow or Credentials is set, and Kind names it
// ("refused" for both refusal fields).
type AuditEvent struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// First is when it began, RFC 3339.
	First *string `json:"first,omitempty"`
	// Last is when it ended, RFC 3339; nil while a session is open.
	Last  *string    `json:"last,omitempty"`
	Count uint64     `json:"count"`
	Actor AuditActor `json:"actor"`

	Access      *AuditAccess       `json:"access,omitempty"`
	Lifecycle   *AuditLifecycle    `json:"lifecycle,omitempty"`
	Policy      *AuditPolicyChange `json:"policy,omitempty"`
	Refused     *AuditRefusal      `json:"refused,omitempty"`
	Credentials *AuditCredentials  `json:"credentials,omitempty"`
	// RefusedOverflow counts an hour's refusals past its 1,000 subjects
	// together; the event's Count is the refusals.
	RefusedOverflow *AuditRefusalOverflow `json:"refused_overflow,omitempty"`
}

// AuditActor is who did it, as they were when it happened: exactly one of
// its fields is set, or none for an actor this SDK does not know yet.
type AuditActor struct {
	User   *AuditUser   `json:"user,omitempty"`
	APIKey *AuditAPIKey `json:"api_key,omitempty"`
	// Platform is the platform's own action.
	Platform *AuditPlatform `json:"platform,omitempty"`
	// Sandbox is what the Sandbox's workload caused.
	Sandbox *AuditSandbox `json:"sandbox,omitempty"`
}

// AuditUser is the person who acted. Role is "owner", "admin", "member" or
// "staff".
type AuditUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type AuditAPIKey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AuditPlatform struct{}

type AuditSandbox struct{}

// AuditAccess is a connection to the Sandbox. Surface is "terminal", "ssh",
// "exec", "desktop" or "preview".
type AuditAccess struct {
	Surface  string `json:"surface"`
	ClientIP string `json:"client_ip"`
}

type AuditSize struct {
	VCPU      uint32 `json:"vcpu"`
	MemoryMiB uint64 `json:"memory_mib"`
}

// AuditLifecycle is a lifecycle change. Action is "created", "started",
// "stopped", "restarted", "resized", "snapshot_taken" or "deleted". Reason is
// why the platform did it, such as "idle", and "" when a person did.
type AuditLifecycle struct {
	Action       string     `json:"action"`
	Reason       string     `json:"reason"`
	Preset       string     `json:"preset"`
	FromSnapshot string     `json:"from_snapshot"`
	From         *AuditSize `json:"from,omitempty"`
	To           *AuditSize `json:"to,omitempty"`
	Snapshot     string     `json:"snapshot"`
	// IdleStopSeconds is, for an idle stop, the idle timeout the Sandbox had
	// then; 0 when not known.
	IdleStopSeconds uint32 `json:"idle_stop_seconds"`
}

// AuditPolicyChange is a network policy change. Action is "selected",
// "edited", "enforcing" or "failed_closed".
type AuditPolicyChange struct {
	Action       string   `json:"action"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	Policy       string   `json:"policy"`
	FromRevision uint32   `json:"from_revision"`
	ToRevision   uint32   `json:"to_revision"`
	Added        []string `json:"added"`
	Removed      []string `json:"removed"`
	Revision     uint32   `json:"revision"`
	FailureCode  string   `json:"failure_code"`
}

// AuditRefusal is an egress refusal. Protocol is "dns", "tcp" or "udp".
type AuditRefusal struct {
	Destination string `json:"destination"`
	Withheld    bool   `json:"withheld"`
	Address     string `json:"address"`
	// Port is nil for DNS.
	Port     *uint32 `json:"port,omitempty"`
	Protocol string  `json:"protocol"`
	Reason   string  `json:"reason"`
	Source   string  `json:"source"`
	Policy   string  `json:"policy"`
	Revision uint32  `json:"revision"`
	// AllowedSinceRevision is the first revision of the selected policy that
	// allows it, when its current revision does; nil otherwise.
	AllowedSinceRevision *uint32 `json:"allowed_since_revision,omitempty"`
}

// AuditRefusalOverflow is how many more subjects were refused that hour;
// AtLeast is true past 1,000 more, which are not counted exactly.
type AuditRefusalOverflow struct {
	Subjects uint64 `json:"subjects"`
	AtLeast  bool   `json:"at_least"`
}

// AuditCredentials is a credential event. Action is "attached", "detached"
// or "used".
type AuditCredentials struct {
	Action   string `json:"action"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Withheld bool   `json:"withheld"`
}

// AuditService reads a hosted Sandbox's audit log (#6189). A user's session
// or an API key reads it; organization owners and admins read every
// Sandbox's events, a member those of each Sandbox they can open now.
type AuditService struct{ client *Client }

func auditEnumName(value protoreflect.Enum, prefix string) string {
	if value.Number() == 0 {
		return ""
	}
	known := value.Descriptor().Values().ByNumber(value.Number())
	if known == nil {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(string(known.Name()), prefix))
}

func auditEventKinds(kinds []string) ([]codewirev1.AuditEventKind, error) {
	values := codewirev1.AuditEventKind(0).Descriptor().Values()
	result := make([]codewirev1.AuditEventKind, 0, len(kinds))
	for _, kind := range kinds {
		value := values.ByName(protoreflect.Name("AUDIT_EVENT_KIND_" + strings.ToUpper(kind)))
		if kind == "" || value == nil || value.Number() == 0 {
			return nil, fmt.Errorf("codewire: unknown audit event kind %q", kind)
		}
		result = append(result, codewirev1.AuditEventKind(value.Number()))
	}
	return result, nil
}

var (
	auditCoverageOnce sync.Once
	auditCoverageErr  error
)

// A field added to any audit message, or a message added to audit.proto,
// fails here until this converter carries it. ListAuditEventsRequest is the
// one message it never converts.
func ensureAuditConverterCoverage() error {
	auditCoverageOnce.Do(func() {
		messages := codewirev1.File_codewire_v1_audit_proto.Messages()
		converted := []struct {
			name   protoreflect.Name
			fields map[protoreflect.FieldNumber]protoreflect.Name
		}{
			{"ListAuditEventsResponse", map[protoreflect.FieldNumber]protoreflect.Name{
				1: "environment", 2: "policy", 3: "events", 4: "next_cursor", 5: "left_out"}},
			{"AuditEnvironment", map[protoreflect.FieldNumber]protoreflect.Name{1: "id", 2: "name", 3: "deleted"}},
			{"AuditPolicyRevision", map[protoreflect.FieldNumber]protoreflect.Name{1: "name", 2: "revision"}},
			{"AuditEvent", map[protoreflect.FieldNumber]protoreflect.Name{
				1: "id", 2: "kind", 3: "first", 4: "last", 5: "count", 6: "actor",
				10: "access", 11: "lifecycle", 12: "policy", 13: "refused", 14: "credentials",
				15: "refused_overflow"}},
			{"AuditActor", map[protoreflect.FieldNumber]protoreflect.Name{1: "user", 2: "api_key", 3: "platform", 4: "sandbox"}},
			{"AuditUser", map[protoreflect.FieldNumber]protoreflect.Name{1: "id", 2: "email", 3: "role"}},
			{"AuditApiKey", map[protoreflect.FieldNumber]protoreflect.Name{1: "id", 2: "name"}},
			{"AuditPlatform", map[protoreflect.FieldNumber]protoreflect.Name{}},
			{"AuditSandbox", map[protoreflect.FieldNumber]protoreflect.Name{}},
			{"AuditAccess", map[protoreflect.FieldNumber]protoreflect.Name{1: "surface", 2: "client_ip"}},
			{"AuditSize", map[protoreflect.FieldNumber]protoreflect.Name{1: "vcpu", 2: "memory_mib"}},
			{"AuditLifecycle", map[protoreflect.FieldNumber]protoreflect.Name{
				1: "action", 2: "reason", 3: "preset", 4: "from_snapshot", 5: "from", 6: "to", 7: "snapshot",
				8: "idle_stop_seconds"}},
			{"AuditPolicyChange", map[protoreflect.FieldNumber]protoreflect.Name{
				1: "action", 2: "from", 3: "to", 4: "policy", 5: "from_revision", 6: "to_revision",
				7: "added", 8: "removed", 9: "revision", 10: "failure_code"}},
			{"AuditRefusal", map[protoreflect.FieldNumber]protoreflect.Name{
				1: "destination", 2: "withheld", 3: "address", 4: "port", 5: "protocol", 6: "reason",
				7: "source", 8: "policy", 9: "revision", 10: "allowed_since_revision"}},
			{"AuditRefusalOverflow", map[protoreflect.FieldNumber]protoreflect.Name{1: "subjects", 2: "at_least"}},
			{"AuditCredentials", map[protoreflect.FieldNumber]protoreflect.Name{
				1: "action", 2: "provider", 3: "name", 4: "host", 5: "withheld"}},
		}
		if messages.Len()-1 != len(converted) {
			auditCoverageErr = fmt.Errorf("codewire: audit converter covers %d messages, audit.proto has %d besides the request", len(converted), messages.Len()-1)
			return
		}
		for _, message := range converted {
			descriptor := messages.ByName(message.name)
			if descriptor == nil {
				auditCoverageErr = fmt.Errorf("codewire: audit converter names %s, which audit.proto lacks", message.name)
				return
			}
			if auditCoverageErr = ensureDescriptorCoverage("audit "+string(message.name), descriptor, message.fields); auditCoverageErr != nil {
				return
			}
		}
	})
	return auditCoverageErr
}

func fromProtoAuditSize(size *codewirev1.AuditSize) *AuditSize {
	if size == nil {
		return nil
	}
	return &AuditSize{VCPU: size.GetVcpu(), MemoryMiB: size.GetMemoryMib()}
}

func fromProtoAuditActor(actor *codewirev1.AuditActor) AuditActor {
	switch value := actor.GetActor().(type) {
	case *codewirev1.AuditActor_User:
		return AuditActor{User: &AuditUser{ID: value.User.GetId(), Email: value.User.GetEmail(),
			Role: auditEnumName(value.User.GetRole(), "AUDIT_ROLE_")}}
	case *codewirev1.AuditActor_ApiKey:
		return AuditActor{APIKey: &AuditAPIKey{ID: value.ApiKey.GetId(), Name: value.ApiKey.GetName()}}
	case *codewirev1.AuditActor_Platform:
		return AuditActor{Platform: &AuditPlatform{}}
	case *codewirev1.AuditActor_Sandbox:
		return AuditActor{Sandbox: &AuditSandbox{}}
	}
	return AuditActor{}
}

func fromProtoAuditEvent(event *codewirev1.AuditEvent) AuditEvent {
	result := AuditEvent{ID: event.GetId(), Kind: auditEnumName(event.GetKind(), "AUDIT_EVENT_KIND_"),
		First: rfc3339(event.GetFirst()), Last: rfc3339(event.GetLast()), Count: event.GetCount(),
		Actor: fromProtoAuditActor(event.GetActor())}
	switch detail := event.GetDetail().(type) {
	case *codewirev1.AuditEvent_Access:
		result.Access = &AuditAccess{Surface: auditEnumName(detail.Access.GetSurface(), "AUDIT_SURFACE_"),
			ClientIP: detail.Access.GetClientIp()}
	case *codewirev1.AuditEvent_Lifecycle:
		value := detail.Lifecycle
		result.Lifecycle = &AuditLifecycle{Action: auditEnumName(value.GetAction(), "ACTION_"),
			Reason: auditEnumName(value.GetReason(), "AUDIT_PLATFORM_REASON_"), Preset: value.GetPreset(),
			FromSnapshot: value.GetFromSnapshot(), From: fromProtoAuditSize(value.GetFrom()),
			To: fromProtoAuditSize(value.GetTo()), Snapshot: value.GetSnapshot(),
			IdleStopSeconds: value.GetIdleStopSeconds()}
	case *codewirev1.AuditEvent_Policy:
		value := detail.Policy
		result.Policy = &AuditPolicyChange{Action: auditEnumName(value.GetAction(), "ACTION_"),
			From: value.GetFrom(), To: value.GetTo(), Policy: value.GetPolicy(),
			FromRevision: value.GetFromRevision(), ToRevision: value.GetToRevision(),
			Added: append([]string{}, value.GetAdded()...), Removed: append([]string{}, value.GetRemoved()...),
			Revision: value.GetRevision(), FailureCode: value.GetFailureCode()}
	case *codewirev1.AuditEvent_Refused:
		value := detail.Refused
		result.Refused = &AuditRefusal{Destination: value.GetDestination(), Withheld: value.GetWithheld(),
			Address: value.GetAddress(), Port: value.Port,
			Protocol: auditEnumName(value.GetProtocol(), "AUDIT_PROTOCOL_"), Reason: value.GetReason(),
			Source: value.GetSource(), Policy: value.GetPolicy(), Revision: value.GetRevision(),
			AllowedSinceRevision: value.AllowedSinceRevision}
	case *codewirev1.AuditEvent_RefusedOverflow:
		result.RefusedOverflow = &AuditRefusalOverflow{Subjects: detail.RefusedOverflow.GetSubjects(),
			AtLeast: detail.RefusedOverflow.GetAtLeast()}
	case *codewirev1.AuditEvent_Credentials:
		value := detail.Credentials
		result.Credentials = &AuditCredentials{Action: auditEnumName(value.GetAction(), "ACTION_"),
			Provider: value.GetProvider(), Name: value.GetName(), Host: value.GetHost(), Withheld: value.GetWithheld()}
	}
	return result
}

func fromProtoAuditEventPage(response *codewirev1.ListAuditEventsResponse) (*AuditEventPage, error) {
	if err := ensureAuditConverterCoverage(); err != nil {
		return nil, err
	}
	environment := response.GetEnvironment()
	if environment == nil {
		return nil, fmt.Errorf("codewire: audit response omitted environment")
	}
	page := &AuditEventPage{
		Environment: AuditEnvironment{ID: environment.GetId(), Name: environment.GetName(), Deleted: environment.GetDeleted()},
		Events:      make([]AuditEvent, 0, len(response.GetEvents())),
		NextCursor:  response.GetNextCursor(), LeftOut: response.GetLeftOut()}
	if policy := response.GetPolicy(); policy != nil {
		page.Policy = &AuditPolicyRevision{Name: policy.GetName(), Revision: policy.GetRevision()}
	}
	for _, event := range response.GetEvents() {
		page.Events = append(page.Events, fromProtoAuditEvent(event))
	}
	return page, nil
}

// ListAuditEvents returns one page of an environment's events, newest first
// by when each began.
func (s *AuditService) ListAuditEvents(ctx context.Context, options ListAuditEventsOptions) (*AuditEventPage, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	kinds, err := auditEventKinds(options.Kinds)
	if err != nil {
		return nil, err
	}
	request := &codewirev1.ListAuditEventsRequest{OrgId: orgID, Kinds: kinds, Limit: options.Limit,
		Cursor: options.Cursor, GroupBySubject: options.GroupBySubject}
	switch {
	case options.EnvironmentID != "" && options.EnvironmentName == "":
		request.Environment = &codewirev1.ListAuditEventsRequest_EnvironmentId{EnvironmentId: options.EnvironmentID}
	case options.EnvironmentName != "" && options.EnvironmentID == "":
		request.Environment = &codewirev1.ListAuditEventsRequest_EnvironmentName{EnvironmentName: options.EnvironmentName}
	default:
		return nil, fmt.Errorf("codewire: an audit read names its environment by exactly one of EnvironmentID or EnvironmentName")
	}
	if !options.Since.IsZero() {
		request.Since = timestamppb.New(options.Since)
	}
	if !options.Until.IsZero() {
		request.Until = timestamppb.New(options.Until)
	}
	response, err := s.client.audit.ListAuditEvents(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoAuditEventPage(response.Msg)
}
