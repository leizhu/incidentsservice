package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	elastic "gopkg.in/olivere/elastic.v5"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/leizhu/incidentsservice/logutil"
)

func init() {
	//log.SetFormatter(&log.JSONFormatter{})
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.AddHook(logutil.ContextHook{})
}

type (
	IncidentsController struct{}

	Response struct {
		ResponseCode int    `json:"responseCode"`
		Message      string `json:"message,omitempty"`
	}

	QueryResponse struct {
		Response
		Data []*elastic.SearchHit `json:"data"`
	}

	AggregationResponse struct {
		Response
		Data *elastic.AggregationTopHitsMetric `json:"data,omitempty"`
	}

	SpsAuthResponse struct {
		ResponseCode int  `json:"responseCode"`
		Data         bool `json:"data"`
	}

	Filters struct {
		PageFrom                       int    `json:"from,omitempty"`
		PageSize                       int    `json:"size,omitempty"`
		StartTimestamp                 string `json:"start_timestamp,omitempty"`
		EndTimestamp                   string `json:"end_timestamp,omitempty"`
		PolicyName                     string `json:"policy,omitempty"`
		ChannelTypeCode                int    `json:"channel,omitempty"`
		ActionTypeCode                 int    `json:"action,omitempty"`
		SourceEntryInfoCommonName      string `json:"source,omitempty"`
		DestinationEntryInfoCommonName string `json:"dest,omitempty"`
		User                           string `json:"user,omitempty"`
	}
)

func NewIncidentsController() *IncidentsController {
	return &IncidentsController{}
}

func NewFilters() Filters {
	f := Filters{}
	f.ActionTypeCode = -1
	f.ChannelTypeCode = -1
	f.PageFrom = 0
	f.PageSize = 20
	return f
}

const (
	es_url             = "http://172.22.112.251:9200"
	sps_auth_url       = "https://sps-webservice:8443/sps/v1/tenant/verify"
	response_success   = 200
	response_fail      = 500
	response_auth_fail = 401
)

func (ic IncidentsController) sps_auth_check(token string) bool {
	client := &http.Client{}
	req, err := http.NewRequest("GET", sps_auth_url, nil)
	if err != nil {
		log.Error("Sending sps_auth request error: " + err.Error())
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		log.Error("Response from sps_auth request is wrong, StatusCode %d", resp.StatusCode)
		return false
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Can not parse response body from sps_auth request: " + err.Error())
		return false
	}
	var s SpsAuthResponse
	json.Unmarshal(body, &s)
	if s.ResponseCode != 200 {
		return false
	} else {
		return s.Data
	}
}

func (ic IncidentsController) es_client(index string) (*elastic.Client, context.Context, error) {
	ctx := context.Background()
	client, err := elastic.NewClient(elastic.SetURL(es_url))
	if err != nil {
		log.Error("Can not create es client: " + err.Error())
		return nil, nil, errors.New(fmt.Sprintln("Can not create es client: ", err))
	}
	info, code, err := client.Ping(es_url).Do(ctx)
	if err != nil {
		log.Error("Elasticsearch returned with code %d and version %s", code, info.Version.Number)
		return nil, nil, errors.New(fmt.Sprintln("Elasticsearch returned with code %d and version %s", code, info.Version.Number))
	}
	exists, err := client.IndexExists(index).Do(ctx)
	if err != nil || !exists {
		log.Error("No index in ES server: " + err.Error())
		return nil, nil, errors.New(fmt.Sprintln("No index in ES server: ", err))
	}
	return client, ctx, nil
}

func (ic IncidentsController) fail_response(code int, errMsg string) string {
	resp := Response{ResponseCode: code, Message: errMsg}
	response, _ := json.Marshal(resp)
	log.Error("Failed Response: " + string(response))
	return string(response)
}

func (ic IncidentsController) header_auth(token string) string {
	if token == "" {
		return "Authorization header should be set."
	}
	s := strings.Split(token, " ")
	if len(s) != 2 {
		return "Authorization header's format is not correct."
	}
	ret := ic.sps_auth_check(s[1])
	if ret {
		return ""
	} else {
		return "Authorization failed from sps"
	}
}

func (ic IncidentsController) GetIncident(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	//errMsg := ic.header_auth(r.Header.Get("Authorization"))
	//if errMsg != "" {
	//	fmt.Fprintf(w, ic.fail_response(response_auth_fail, errMsg))
	//	return
	//}
	es_index := "incidents-" + p.ByName("tenant")
	es_type := p.ByName("incident_type")
	query_id := p.ByName("query_id")
	log.WithFields(log.Fields{
		"es_index": es_index,
		"query_id": query_id,
	}).Info("Execute /cloud/v1/incident api.")

	w.Header().Set("Content-Type", "application/json")
	client, ctx, err := ic.es_client(es_index)
	if err != nil {
		fmt.Fprintf(w, ic.fail_response(response_fail, err.Error()))
		return
	}

	// Search with a term query
	termQuery := elastic.NewTermQuery("id", query_id)
	searchResult, err := client.Search().
		Index(es_index).
		Type(es_type).
		Query(termQuery). // specify the query
		Sort("detectTime", true).
		From(0).Size(10).
		Pretty(true).
		Do(ctx) // execute
	if err != nil {
		fmt.Fprintf(w, ic.fail_response(response_fail, "Encouter error when search with a term query: "+err.Error()))
	} else {
		resp := QueryResponse{}
		resp.ResponseCode = response_success
		f := []*elastic.SearchHit{}
		if searchResult.Hits.TotalHits > 0 {
			resp.Data = searchResult.Hits.Hits
		} else {
			resp.Data = f
		}
		response, _ := json.Marshal(resp)
		log.Debug("response is: " + string(response))
		fmt.Fprintf(w, string(response))
	}
}

func (ic IncidentsController) GetReport(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	//errMsg := ic.header_auth(r.Header.Get("Authorization"))
	//if errMsg != "" {
	//      fmt.Fprintf(w, ic.fail_response(response_auth_fail, errMsg))
	//      return
	//}
	es_index := "incidents-" + p.ByName("tenant")
	es_type := p.ByName("incident_type")
	queryValues := r.URL.Query()
	var agg_type string
	agg_type = queryValues.Get("agg_type")
	if agg_type == "" {
		agg_type = "1"
	}
	var agg_size int
	if agg_top := queryValues.Get("agg_top"); agg_top != "" {
		if size, err := strconv.Atoi(agg_top); err != nil {
			agg_size = 10
		} else {
			agg_size = size
		}
	}
	log.WithFields(log.Fields{
		"es_index": es_index,
		"agg_type": agg_type,
		"agg_top":  agg_size,
	}).Info("Execute /cloud/v1/report api.")

	w.Header().Set("Content-Type", "application/json")
	client, ctx, err := ic.es_client(es_index)
	if err != nil {
		fmt.Fprintf(w, ic.fail_response(response_fail, err.Error()))
		return
	}

	var agg_type_map = map[string]string{"1": "incidentPolicies.policyName.keyword", "2": "sourceEntryInfo.commonName.keyword", "3": "incidentDestinations.destinationEntryInfo.commonName.keyword", "4": "channelTypeCode"}
	var agg_field string
	var exists bool
	agg_field, exists = agg_type_map[agg_type]
	if !exists {
		agg_field = "incidentPolicies.policyName.keyword"
	}
	termsAggregation := elastic.NewTermsAggregation().Field(agg_field).Size(agg_size)
	builder := client.Search().Index(es_index).Type(es_type).Pretty(true).Aggregation("sort_incidents", termsAggregation)
	searchResult, err := builder.Do(ctx)
	if err != nil {
		fmt.Fprintf(w, ic.fail_response(response_fail, "Encouter error when executing an aggregation: "+err.Error()))
	} else {
		agg := searchResult.Aggregations
		if agg == nil {
			fmt.Fprintf(w, ic.fail_response(response_fail, "expected Aggregations != nil; got: nil"))
		}
		resp := AggregationResponse{}
		var b bool
		resp.Data, b = agg.TopHits("sort_incidents")
		if b {
			resp.ResponseCode = response_success
		} else {
			resp.ResponseCode = response_fail
		}
		response, _ := json.Marshal(resp)
		log.Debug("response is: " + string(response))
		fmt.Fprintf(w, string(response))
	}
}

func (ic IncidentsController) constructFilters(r *http.Request) Filters {
	queryValues := r.URL.Query()
	filters := NewFilters()
	filters.StartTimestamp = queryValues.Get("start_timestamp")
	filters.EndTimestamp = queryValues.Get("end_timestamp")
	filters.PolicyName = queryValues.Get("policy")
	filters.SourceEntryInfoCommonName = queryValues.Get("source")
	filters.DestinationEntryInfoCommonName = queryValues.Get("dest")
	filters.User = queryValues.Get("user")
	if para_from := queryValues.Get("from"); para_from != "" {
		if from, err := strconv.Atoi(para_from); err != nil {
			filters.PageFrom = 20
		} else {
			filters.PageFrom = from
		}
	}
	if para_size := queryValues.Get("size"); para_size != "" {
		if size, err := strconv.Atoi(para_size); err != nil {
			filters.PageSize = 20
		} else {
			filters.PageSize = size
		}
	}
	if para_action := queryValues.Get("action"); para_action != "" {
		if action, err := strconv.Atoi(para_action); err == nil {
			filters.ActionTypeCode = action
		}
	}
	if para_channel := queryValues.Get("channel"); para_channel != "" {
		if channel, err := strconv.Atoi(para_channel); err == nil {
			filters.ChannelTypeCode = channel
		}
	}
	return filters
}

func (ic IncidentsController) SearchIncidents(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	//errMsg := ic.header_auth(r.Header.Get("Authorization"))
	//if errMsg != "" {
	//      fmt.Fprintf(w, ic.fail_response(response_auth_fail, errMsg))
	//      return
	//}
	es_index := "incidents-" + p.ByName("tenant")
	es_type := p.ByName("incident_type")

	filters := ic.constructFilters(r)
	f_str, _ := json.Marshal(filters)
	log.WithFields(log.Fields{
		"es_index": es_index,
		"es_type":  es_type,
		"filters":  string(f_str),
	}).Info("Execute /cloud/v1/incidents api.")

	w.Header().Set("Content-Type", "application/json")
	client, ctx, err := ic.es_client(es_index)
	if err != nil {
		fmt.Fprintf(w, ic.fail_response(response_fail, err.Error()))
		return
	}
	boolQuery := elastic.NewBoolQuery().QueryName("bool_query")
	if filters.ActionTypeCode != -1 {
		boolQuery.Must(elastic.NewTermQuery("actionTypeCode", filters.ActionTypeCode))
	}
	if filters.ChannelTypeCode != -1 {
		boolQuery.Must(elastic.NewTermQuery("channelTypeCode", filters.ChannelTypeCode))
	}
	if filters.PolicyName != "" {
		boolQuery.Must(elastic.NewMatchQuery("incidentPolicies.policyName", filters.PolicyName).Operator("and"))
	}
	if filters.SourceEntryInfoCommonName != "" {
		boolQuery.Must(elastic.NewMatchPhraseQuery("sourceEntryInfo.commonName", filters.SourceEntryInfoCommonName))
	}
	if filters.DestinationEntryInfoCommonName != "" {
		boolQuery.Must(elastic.NewMatchPhraseQuery("incidentDestinations.destinationEntryInfo.commonName", filters.DestinationEntryInfoCommonName))
	}
	if filters.User != "" {
		boolQuery.Must(elastic.NewMatchPhraseQuery("sourceEntryInfo.commonName", filters.User))
	}
	fsc := elastic.NewFetchSourceContext(true).Include("id", "incidentProperties.queryUUID", "tenant")
	searchResult, err := client.Search().FetchSourceContext(fsc).Index(es_index).Type(es_type).Query(boolQuery).Sort("detectTime", true).
		From(filters.PageFrom).Size(filters.PageSize).Pretty(true).Do(ctx) // execute
	if err != nil {
		fmt.Fprintf(w, ic.fail_response(response_fail, "Encouter error when search with filters: "+err.Error()))
	} else {
		resp := QueryResponse{}
		resp.ResponseCode = response_success
		f := []*elastic.SearchHit{}
		if searchResult.Hits.TotalHits > 0 {
			resp.Data = searchResult.Hits.Hits
		} else {
			resp.Data = f
		}
		response, _ := json.Marshal(resp)
		log.Debug("response is: " + string(response))
		fmt.Fprintf(w, string(response))
	}

}
