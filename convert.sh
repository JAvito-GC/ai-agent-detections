#!/usr/bin/env bash
# Regenerate SIEM queries from the Sigma rules with the OSS sigma-cli.
#   pip install pySigma==1.5.1 pySigma-backend-elasticsearch==2.1.1 pySigma-backend-kusto==1.0.1 pysigma-backend-splunk==2.1.0 sigma-cli==3.1.0
set -euo pipefail
cd "$(dirname "$0")"
rm -rf conversions && mkdir -p conversions/{splunk,sentinel,elastic-esql}
for rule in rules/*.yml; do
  name=$(basename "$rule" .yml)
  sigma convert -t splunk --without-pipeline "$rule" > "conversions/splunk/$name.spl"
  sigma convert -t kusto  -p pipelines/sentinel.yml "$rule" > "conversions/sentinel/$name.kql"
  sigma convert -t esql   -p pipelines/elastic-esql.yml "$rule" > "conversions/elastic-esql/$name.esql"
done
echo "converted $(ls rules/*.yml | wc -l | tr -d ' ') rules x 3 targets"
