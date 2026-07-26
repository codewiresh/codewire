export const TEST_PASSWORD = "SecureTestPass9#";

export const USERS = {
  master:   { email: "e2e-master@codewire.sh",   name: "E2E Master",   isAdmin: false },
  owner:    { email: "e2e-owner@codewire.sh",     name: "E2E Owner",    isAdmin: false },
  member:   { email: "e2e-member@codewire.sh",    name: "E2E Member",   isAdmin: false },
  outsider: { email: "e2e-outsider@codewire.sh",  name: "E2E Outsider", isAdmin: false },
  admin:    { email: "e2e-admin@codewire.sh",      name: "E2E Admin",    isAdmin: true },
  billing:  { email: "e2e-billing@codewire.sh",   name: "E2E Billing",  isAdmin: false },
} as const;
