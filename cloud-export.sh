#!/usr/bin/env bash
# Copyright 2026 Yusuke Hirose
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# 外部公開資産とセキュリティ設定を CSV に出力する（AWS CLI のみ使用）
#
# AWS CloudShell での実行を想定しています。
# 追加のインストールは不要で、認証情報は環境から出ません。
# 実行するのは参照系のAPIのみで、作成・変更・削除は一切行いません。
#
#   使い方:  bash cloud-export.sh
#   出力:    cloud-manual.csv / cloud-risks-manual.csv / route53-domains.txt
#
#   対象リージョンを絞る場合:
#       REGIONS="ap-northeast-1 us-east-1" bash cloud-export.sh
set -uo pipefail

OUT_ASSETS="cloud-manual.csv"
OUT_RISKS="cloud-risks-manual.csv"
OUT_SEEDS="route53-domains.txt"

echo "provider,resource_type,resource_id,dns_name,ip,region" > "$OUT_ASSETS"
echo "provider,resource_id,risk_id,severity,detail"          > "$OUT_RISKS"
: > "$OUT_SEEDS"

# 危険なポート（0.0.0.0/0 開放時に critical 扱いにする）
CRIT_PORTS='[22,23,445,1433,3306,3389,5432,5900,6379,9200,11211,27017]'

echo "== 実行アカウント =========================================="
aws sts get-caller-identity --output table || {
  echo "AWS の認証に失敗しました。ログイン状態を確認してください。" >&2
  exit 1
}

if [[ -z "${REGIONS:-}" ]]; then
  echo "有効なリージョンを取得しています..."
  REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null | tr '\t' ' ')
fi
[[ -z "$REGIONS" ]] && REGIONS="ap-northeast-1"
echo "対象リージョン: $REGIONS"
echo ""

q() { aws "$@" 2>/dev/null; }   # 権限不足のリージョンは黙って飛ばす

# ==========================================================
# グローバルなリソース
# ==========================================================
echo "== グローバル =============================================="

echo -n "  CloudFront ... "
q cloudfront list-distributions --output json \
  | jq -r '.DistributionList.Items[]? | select(.Enabled == true)
           | ["aws","cloudfront", .ARN, .DomainName, "", "global"] | @csv' \
  >> "$OUT_ASSETS"
echo "ok"

echo -n "  Route53 (公開ゾーン) ... "
q route53 list-hosted-zones --output json \
  | jq -r '.HostedZones[]? | select(.Config.PrivateZone == false)
           | .Name | rtrimstr(".")' \
  | sort -u >> "$OUT_SEEDS"
echo "$(wc -l < "$OUT_SEEDS") 件"

echo -n "  S3 (公開設定のバケット) ... "
s3n=0
for b in $(q s3api list-buckets --query 'Buckets[].Name' --output text); do
  pol=$(q s3api get-bucket-policy-status --bucket "$b" \
        --query 'PolicyStatus.IsPublic' --output text || echo "None")
  blk=$(q s3api get-public-access-block --bucket "$b" \
        --query 'PublicAccessBlockConfiguration.BlockPublicPolicy' --output text || echo "None")
  if [[ "$pol" == "True" || "$blk" != "True" ]]; then
    loc=$(q s3api get-bucket-location --bucket "$b" \
          --query 'LocationConstraint' --output text || echo "us-east-1")
    [[ "$loc" == "None" || -z "$loc" ]] && loc="us-east-1"
    printf '"aws","s3","arn:aws:s3:::%s","%s.s3.amazonaws.com","","%s"\n' "$b" "$b" "$loc" >> "$OUT_ASSETS"
    if [[ "$pol" == "True" ]]; then
      printf '"aws","arn:aws:s3:::%s","s3-public-access","critical","S3 bucket %s is publicly accessible"\n' \
        "$b" "$b" >> "$OUT_RISKS"
    fi
    s3n=$((s3n + 1))
  fi
done
echo "$s3n 件"

echo -n "  IAM (180日以上未更新のアクセスキー) ... "
iamn=0
cutoff=$(date -u -d '180 days ago' +%Y-%m-%d 2>/dev/null || date -u -v-180d +%Y-%m-%d)
for u in $(q iam list-users --query 'Users[].UserName' --output text); do
  while read -r kid cdate; do
    [[ -z "${kid:-}" ]] && continue
    if [[ "${cdate:0:10}" < "$cutoff" ]]; then
      printf '"aws","%s","iam-key-stale","medium","IAM user %s has an access key created on %s"\n' \
        "$u" "$u" "${cdate:0:10}" >> "$OUT_RISKS"
      iamn=$((iamn + 1))
    fi
  done < <(q iam list-access-keys --user-name "$u" \
           --query "AccessKeyMetadata[?Status=='Active'].[AccessKeyId,CreateDate]" --output text)
done
echo "$iamn 件"
echo ""

# ==========================================================
# リージョンごとのリソース
# ==========================================================
for r in $REGIONS; do
  echo "== $r =========================================="

  echo -n "  ALB / NLB ... "
  q elbv2 describe-load-balancers --region "$r" --output json \
    | jq -r --arg r "$r" '.LoadBalancers[]? | select(.Scheme == "internet-facing")
             | ["aws", (if .Type == "network" then "nlb" else "alb" end),
                .LoadBalancerArn, .DNSName, "", $r] | @csv' >> "$OUT_ASSETS"
  q elb describe-load-balancers --region "$r" --output json \
    | jq -r --arg r "$r" '.LoadBalancerDescriptions[]? | select(.Scheme == "internet-facing")
             | ["aws","clb", .LoadBalancerName, .DNSName, "", $r] | @csv' >> "$OUT_ASSETS"
  echo "ok"

  echo -n "  EC2 (パブリックIP付き) ... "
  q ec2 describe-instances --region "$r" \
      --filters Name=instance-state-name,Values=running --output json \
    | jq -r --arg r "$r" '.Reservations[]?.Instances[]? | select(.PublicIpAddress != null)
             | ["aws","ec2", .InstanceId, (.PublicDnsName // ""), .PublicIpAddress, $r] | @csv' \
    >> "$OUT_ASSETS"
  echo "ok"

  echo -n "  Elastic IP ... "
  q ec2 describe-addresses --region "$r" --output json \
    | jq -r --arg r "$r" '.Addresses[]? | select(.PublicIp != null)
             | ["aws","eip", ("eip:" + (.AllocationId // .PublicIp)), "", .PublicIp, $r] | @csv' \
    >> "$OUT_ASSETS"
  echo "ok"

  echo -n "  RDS (外部公開) ... "
  q rds describe-db-instances --region "$r" --output json \
    | jq -r --arg r "$r" '.DBInstances[]? | select(.PubliclyAccessible == true)
             | ["aws","rds", .DBInstanceArn, (.Endpoint.Address // ""), "", $r] | @csv' \
    >> "$OUT_ASSETS"
  q rds describe-db-instances --region "$r" --output json \
    | jq -r '.DBInstances[]? | select(.PubliclyAccessible == true)
             | ["aws", .DBInstanceArn, "rds-publicly-accessible", "high",
                ("RDS instance " + .DBInstanceIdentifier + " is publicly accessible")] | @csv' \
    >> "$OUT_RISKS"
  q rds describe-db-instances --region "$r" --output json \
    | jq -r '.DBInstances[]? | select(.StorageEncrypted == false)
             | ["aws", .DBInstanceArn, "rds-not-encrypted", "medium",
                ("RDS instance " + .DBInstanceIdentifier + " is not encrypted")] | @csv' \
    >> "$OUT_RISKS"
  echo "ok"

  echo -n "  API Gateway ... "
  q apigatewayv2 get-apis --region "$r" --output json \
    | jq -r --arg r "$r" '.Items[]? | ["aws","apigateway", .ApiId,
             ((.ApiEndpoint // "") | sub("^https://"; "")), "", $r] | @csv' >> "$OUT_ASSETS"
  echo "ok"

  echo -n "  セキュリティグループ (0.0.0.0/0 開放) ... "
  q ec2 describe-security-groups --region "$r" --output json \
    | jq -r --argjson crit "$CRIT_PORTS" '
        .SecurityGroups[]? as $sg
        | $sg.IpPermissions[]? as $p
        | ($p.IpRanges[]? | select(.CidrIp == "0.0.0.0/0"))
        | ["aws", $sg.GroupId, "sg-open-to-world",
           (if ($crit | index($p.FromPort)) then "critical" else "high" end),
           ("Security group " + $sg.GroupName + " allows "
            + (($p.FromPort // "all") | tostring) + "/" + $p.IpProtocol
            + " from 0.0.0.0/0")] | @csv' >> "$OUT_RISKS"
  echo "ok"

  echo -n "  EBS (未暗号化) ... "
  q ec2 describe-volumes --region "$r" --output json \
    | jq -r '.Volumes[]? | select(.Encrypted == false)
             | ["aws", .VolumeId, "ebs-not-encrypted", "medium",
                ("EBS volume " + .VolumeId + " is not encrypted")] | @csv' >> "$OUT_RISKS"
  echo "ok"

  echo -n "  ACM (30日以内に失効) ... "
  limit=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -u -v+30d +%Y-%m-%dT%H:%M:%S)
  q acm list-certificates --region "$r" --output json \
    | jq -r --arg limit "$limit" '.CertificateSummaryList[]?
             | select(.NotAfter != null and (.NotAfter | tostring) < $limit)
             | ["aws", .CertificateArn, "acm-cert-expiring", "medium",
                ("ACM certificate " + .DomainName + " expires at " + (.NotAfter | tostring))] | @csv' \
    >> "$OUT_RISKS"
  echo "ok"
done

echo ""
echo "============================================================"
echo " 完了"
echo "   $OUT_ASSETS : $(( $(wc -l < "$OUT_ASSETS") - 1 )) 件"
echo "   $OUT_RISKS  : $(( $(wc -l < "$OUT_RISKS")  - 1 )) 件"
echo "   $OUT_SEEDS  : $(wc -l < "$OUT_SEEDS") 件"
echo "============================================================"
echo ""
echo "中身を確認してからお渡しください:"
echo "   head -20 $OUT_ASSETS"
echo ""
echo "ダウンロード: 画面右上の Actions → Download file"
echo "   $(pwd)/$OUT_ASSETS"
echo "   $(pwd)/$OUT_RISKS"
