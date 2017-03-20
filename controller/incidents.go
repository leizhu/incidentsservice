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
		Data []*elastic.SearchHit `json:"data,omitempty"`
	}

	AggregationResponse struct {
		Response
		Data *elastic.AggregationTopHitsMetric `json:"data,omitempty"`
	}

	SpsAuthResponse struct {
		ResponseCode int  `json:"responseCode"`
		Data         bool `json:"data"`
	}
)

func NewIncidentsController() *IncidentsController {
	return &IncidentsController{}
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
		var f []*elastic.SearchHit
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
	agg_type := p.ByName("agg_type")
	var agg_size int
	if agg_top := p.ByName("agg_top"); agg_top != "" {
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
	termsAggregation := elastic.NewTermsAggregation().Field("incidentPolicies.policyName.keyword").Size(agg_size)
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
