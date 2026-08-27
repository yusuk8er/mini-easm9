-- 調査対象ドメイン(シード)を Route53 から自動抽出する
-- 手動メンテしていたドメイン一覧を持たなくてよくなる、という手抜きポイント
-- 実行: steampipe query --output csv queries/aws_seeds.sql

select distinct
  rtrim(name, '.') as domain
from aws_route53_zone
where not private_zone
order by domain
