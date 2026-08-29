-- Copyright 2026 Yusuke Hirose
--
-- SPDX-License-Identifier: Apache-2.0
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- 外部公開されている AWS リソースだけを抽出する
-- 目的: 「クラウドの全資産棚卸し」ではなく「外部から到達しうるもの」に限定する
-- 実行: steampipe query --output csv queries/aws_public.sql

select
  'aws'                          as provider,
  'alb'                          as resource_type,
  arn                            as resource_id,
  dns_name                       as dns_name,
  null                           as ip,
  region                         as region
from aws_ec2_application_load_balancer
where scheme = 'internet-facing'

union all

select
  'aws', 'nlb', arn, dns_name, null, region
from aws_ec2_network_load_balancer
where scheme = 'internet-facing'

union all

select
  'aws', 'cloudfront', arn, domain_name, null, 'global'
from aws_cloudfront_distribution
where enabled

union all

select
  'aws', 'ec2', arn, public_dns_name, public_ip_address, region
from aws_ec2_instance
where public_ip_address is not null
  and instance_state = 'running'

union all

select
  'aws', 'rds', arn, endpoint_address, null, region
from aws_rds_db_instance
where publicly_accessible

union all

select
  'aws', 's3', arn, name || '.s3.amazonaws.com', null, region
from aws_s3_bucket
where bucket_policy_is_public
   or not coalesce(block_public_acls, false)
   or not coalesce(block_public_policy, false)

union all

select
  'aws', 'apigateway', api_id, api_id || '.execute-api.' || region || '.amazonaws.com', null, region
from aws_api_gatewayv2_api

union all

select
  'aws', 'eip', 'eip:' || allocation_id, null, public_ip, region
from aws_vpc_eip
where public_ip is not null

order by resource_type, dns_name
