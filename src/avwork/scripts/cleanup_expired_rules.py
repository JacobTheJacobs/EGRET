from __future__ import annotations

from datetime import datetime, timezone

from app.services.policy.expiry_cleanup import ExpiryCleanupService
from app.storage.repositories.sqlite import SqliteRepositories


def main() -> None:
    repos = SqliteRepositories('egret.db')
    result = ExpiryCleanupService(rules=repos.rules, decisions=repos.decisions).run(
        now=datetime.now(timezone.utc)
    )
    print(
        {
            'expired_rule_count': result.expired_rule_count,
            'expired_decision_count': result.expired_decision_count,
        }
    )


if __name__ == '__main__':
    main()
