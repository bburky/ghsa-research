curl -s $(curl -s 'https://toolbox-data.anchore.io/grype/databases/listing.json' | jq -r '.available["1"][0].url') | tar xz vulnerability.db

echo 'select * from vulnerability where id = "CVE-2024-26147";' |  sqlite3 vulnerability.db

echo 'select * from vulnerability where id = "CVE-2022-29226";' |  sqlite3 vulnerability.db
