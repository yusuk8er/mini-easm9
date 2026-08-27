-- クラウドの設定情報から「確定している」リスクを抽出する
-- 設定値をそのまま読むだけなので誤検知は原理的に発生しない
-- 列: provider, resource_id, risk_id, severity, detail

select
  'aws'                                     as provider,
  group_id                                  as resource_id,
  'sg-open-to-world'                        as risk_id,
  case
    when (perm -> 'FromPort')::int in (22, 3389, 3306, 5432, 1433, 6379, 27017, 9200)
      then 'critical'
    else 'high'
  end                                       as severity,
  'Security group ' || group_name || ' allows '
    || coalesce((perm ->> 'FromPort'), 'all') || '/'
    || coalesce((perm ->> 'IpProtocol'), 'all')
    || ' from 0.0.0.0/0'                as detail
from aws_vpc_security_group,
     jsonb_array_elements(ip_permissions) as perm,
     jsonb_array_elements(perm -> 'IpRanges') as r
where r ->> 'CidrIp' = '0.0.0.0/0'

union all

select
  'aws', arn, 's3-public-access', 'critical',
  'S3 bucket ' || name || ' is publicly accessible'
from aws_s3_bucket
where bucket_policy_is_public

union all

select
  'aws', arn, 'rds-publicly-accessible', 'high',
  'RDS instance ' || db_instance_identifier || ' is publicly accessible'
from aws_rds_db_instance
where publicly_accessible

union all

select
  'aws', arn, 'rds-not-encrypted', 'medium',
  'RDS instance ' || db_instance_identifier || ' is not encrypted'
from aws_rds_db_instance
where not storage_encrypted

union all

select
  'aws', arn, 'ebs-not-encrypted', 'medium',
  'EBS volume ' || volume_id || ' is not encrypted'
from aws_ebs_volume
where not encrypted

union all

select
  'aws', arn, 'acm-cert-expiring', 'medium',
  'ACM certificate ' || domain_name || ' expires within 30 days ('
    || to_char(not_after, 'YYYY-MM-DD') || ')'
from aws_acm_certificate
where not_after < now() + interval '30 days'
  and not_after > now()

union all

select
  'aws', arn, 'iam-key-stale', 'medium',
  'IAM user ' || name || ' has an access key older than 180 days'
from aws_iam_user
where exists (
  select 1 from aws_iam_access_key k
  where k.user_name = aws_iam_user.name
    and k.status = 'Active'
    and k.create_date < now() - interval '180 days'
)

order by severity, risk_id
