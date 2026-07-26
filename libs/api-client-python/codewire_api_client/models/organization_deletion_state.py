from enum import Enum


class OrganizationDeletionState(str, Enum):
    ACTIVE = "active"
    DELETE_FAILED = "delete_failed"
    DELETING = "deleting"

    def __str__(self) -> str:
        return str(self.value)
