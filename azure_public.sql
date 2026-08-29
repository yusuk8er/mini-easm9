-- 外部公開されている Azure リソース
-- 事前に: steampipe plugin install azure
-- 列は aws_public.sql と揃える（provider, resource_type, resource_id, dns_name, ip, region）

-- azure_public_ip の FQDN 列はプラグインのバージョンで名称が異なるため、
-- 確実に存在する ip_address のみを使う（FQDN は外部偵察側で補完される）
select
  'azure'                        as provider,
  'public_ip'                    as resource_type,
  id                             as resource_id,
  null                           as dns_name,
  ip_address                     as ip,
  region                         as region
from azure_public_ip
where ip_address is not null

union all

select
  'azure', 'app_service', id, default_site_hostname, null, region
from azure_app_service_web_app

union all

select
  'azure', 'function_app', id, default_site_hostname, null, region
from azure_app_service_function_app

union all

select
  'azure', 'storage', id, name || '.blob.core.windows.net', null, region
from azure_storage_account
where allow_blob_public_access

union all

select
  'azure', 'sql_server', id, fully_qualified_domain_name, null, region
from azure_sql_server
where public_network_access = 'Enabled'

union all

select
  'azure', 'api_management', id, gateway_url, null, region
from azure_api_management

-- 注: azure_container_app は Steampipe の azure プラグインに存在しないため対象外。
--     Container Apps は外部偵察側（DNS）で検出されます。

order by resource_type, dns_name
