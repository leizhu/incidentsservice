package main

import (
	"flag"
	"github.com/julienschmidt/httprouter"
	"github.com/leizhu/incidentsservice/controller"
	"log"
	"net/http"
)

var (
	listenAddress = flag.String(
		"web.listen-address", ":7443",
		"Address to listen on for web interface and telemetry.",
	)
	es_url = flag.String(
		"elasticsearch.url", "http://elasticsearch:9200",
		"URL of elasticsearch",
	)
	sps_auth_enable = flag.Bool(
		"sps-auth.enable", true,
		"Enable/Disable of sps auth",
	)
	sps_auth_url = flag.String(
		"sps-auth.url", "https://sps-webservice:8443",
		"URL of sps auth service",
	)
	log_level = flag.String(
		"loglevel", "INFO",
		"log level",
	)
)

func main() {
	flag.Parse()
	router := httprouter.New()
	controller.InitLog(*log_level)
	ic := controller.NewIncidentsController(*es_url, *sps_auth_enable, *sps_auth_url)
	router.GET("/cloud/v1/incident/:tenant/:incident_type/:query_id", ic.GetIncident)
	router.GET("/cloud/v1/incidents/:tenant/:incident_type", ic.SearchIncidents)
	router.GET("/cloud/v1/report/:tenant/:incident_type", ic.GetReport)

	log.Println("Starting Server: ", *listenAddress)
	log.Println("elasticsearch.url: ", *es_url)
	log.Println("sps-auth.enable: ", *sps_auth_enable)
	log.Println("sps-auth.url: ", *sps_auth_url)
	log.Println("log level: ", *log_level)
	log.Fatal(http.ListenAndServeTLS(*listenAddress, "/opt/incidentsservice/certs/server.crt", "/opt/incidentsservice/certs/server.key", router))
}
