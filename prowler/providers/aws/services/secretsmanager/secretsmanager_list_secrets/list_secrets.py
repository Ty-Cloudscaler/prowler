from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_list_secrets(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets():
            report = Check_Report_AWS(self.metadata())
            report.region = secret.region
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.resource_tags = secret.tags
            if secret.secrets == null:
                report.status = "FAIL"
                report.status_extended = (
                    f"SecretsManager has no secrets."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"SecretsManager has secrets {secret.name} ."
                )

            findings.append(report)

        return findings