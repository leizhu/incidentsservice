curl -k -X GET "https://172.22.112.252:7443/cloud/v1/incident/tenant1/network/12340011"

curl -k -X GET "https://172.22.112.252:7443/cloud/v1/report/tenant1/network?agg_top=4&agg_type=1" 

curl -k -X GET "https://172.22.112.252:7443/cloud/v1/incidents/tenant1/network?from=0&size=10&policy=policy611-001&action=1&channel=0&source=192.168.1.1&dest=danieldiy@126.com&user=192.168.1.1&start_timestamp=1468294205326&end_timestamp=1470078960000"
