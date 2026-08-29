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

-- 調査対象ドメイン(シード)を Route53 から自動抽出する
-- 手動メンテしていたドメイン一覧を持たなくてよくなる、という手抜きポイント
-- 実行: steampipe query --output csv queries/aws_seeds.sql

select distinct
  rtrim(name, '.') as domain
from aws_route53_zone
where not private_zone
order by domain
