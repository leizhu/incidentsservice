curl -k -X GET "https://172.22.112.252:8888/cloud/v1/incident/tenant1/network/12340011"

curl -k -X GET "https://172.22.112.252:8888/cloud/v1/report/tenant1/network?agg_top=4&agg_type=1" 

curl -k -X GET "https://172.22.112.252:8888/cloud/v1/incidents/tenant1/network?from=0&size=10&policy=policy611-001"
