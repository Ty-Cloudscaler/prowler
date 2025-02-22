from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_server_access_logging_enabled(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets:
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn
            report.resource_tags = bucket.tags
            if bucket.replication:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has replication enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has replication disabled."
                )
            findings.append(report)

        return findings