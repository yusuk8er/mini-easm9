-- 外部公開されている GCP リソース
-- 事前に: steampipe plugin install gcp

select
  'gcp'                          as provider,
  'compute_instance'             as resource_type,
  id::text                       as resource_id,
  null                           as dns_name,
  ni_ac ->> 'natIP'              as ip,
  location                       as region
from gcp_compute_instance,
     jsonb_array_elements(network_interfaces) as ni,
     jsonb_array_elements(coalesce(ni -> 'accessConfigs', '[]'::jsonb)) as ni_ac
where ni_ac ->> 'natIP' is not null
  and status = 'RUNNING'

union all

select
  'gcp', 'forwarding_rule', id::text, null, ip_address, location
from gcp_compute_forwarding_rule
where load_balancing_scheme = 'EXTERNAL'
   or load_balancing_scheme = 'EXTERNAL_MANAGED'

union all

select
  'gcp', 'cloud_run', name, split_part(uri, '//', 2), null, location
from gcp_cloud_run_service
where uri is not null

union all

select
  'gcp', 'storage', id, name || '.storage.googleapis.com', null, location
from gcp_storage_bucket
where iam_policy::text like '%allUsers%'
   or iam_policy::text like '%allAuthenticatedUsers%'

union all

select
  'gcp', 'sql_instance', name, null, ip ->> 'ipAddress', location
from gcp_sql_database_instance,
     jsonb_array_elements(ip_addresses) as ip
where ip ->> 'type' = 'PRIMARY'

union all

select
  'gcp', 'address', id::text, null, address, location
from gcp_compute_address
where address_type = 'EXTERNAL'
  and status = 'IN_USE'

order by resource_type, dns_name
