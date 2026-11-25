package codewire

import (
	"strings"
	"testing"

	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestAuditConverterCoversEveryMessageAndNamesEveryEnumValue(t *testing.T) {
	if err := ensureAuditConverterCoverage(); err != nil {
		t.Fatal(err)
	}
	if _, err := fromProtoAuditEventPage(&codewirev1.ListAuditEventsResponse{}); err == nil {
		t.Fatal("a response without an environment was accepted")
	}
	for _, enum := range []struct {
		value  protoreflect.Enum
		prefix string
	}{
		{codewirev1.AuditEventKind(0), "AUDIT_EVENT_KIND_"},
		{codewirev1.AuditRole(0), "AUDIT_ROLE_"},
		{codewirev1.AuditSurface(0), "AUDIT_SURFACE_"},
		{codewirev1.AuditPlatformReason(0), "AUDIT_PLATFORM_REASON_"},
		{codewirev1.AuditProtocol(0), "AUDIT_PROTOCOL_"},
		{codewirev1.AuditLifecycle_Action(0), "ACTION_"},
		{codewirev1.AuditPolicyChange_Action(0), "ACTION_"},
		{codewirev1.AuditCredentials_Action(0), "ACTION_"},
	} {
		values := enum.value.Descriptor().Values()
		for i := 0; i < values.Len(); i++ {
			value := values.Get(i)
			name := auditEnumName(enum.value.Type().New(value.Number()), enum.prefix)
			switch {
			case value.Number() == 0 && name != "":
				t.Errorf("%s is %q, not empty", value.FullName(), name)
			case value.Number() != 0 && (name == "" || name == "unknown" || strings.ToUpper(enum.prefix+name) != string(value.Name())):
				t.Errorf("%s is %q", value.FullName(), name)
			}
		}
		if name := auditEnumName(enum.value.Type().New(99), enum.prefix); name != "unknown" {
			t.Errorf("%s 99 is %q, not unknown", enum.value.Descriptor().FullName(), name)
		}
	}
	kinds, err := auditEventKinds([]string{"access", "lifecycle", "policy", "refused", "credentials"})
	if err != nil || len(kinds) != 5 || kinds[0] != codewirev1.AuditEventKind_AUDIT_EVENT_KIND_ACCESS ||
		kinds[4] != codewirev1.AuditEventKind_AUDIT_EVENT_KIND_CREDENTIALS {
		t.Fatalf("kinds: %v %v", kinds, err)
	}
}
