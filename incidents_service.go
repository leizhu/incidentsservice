package main

import (
	"github.com/julienschmidt/httprouter"
	"github.com/leizhu/incidentsservice/controller"
	"log"
	"net/http"
)

func main() {
	router := httprouter.New()
	ic := controller.NewIncidentsController()
	router.GET("/cloud/v1/incident/:tenant/:incident_type/:query_id", ic.GetIncident)
	router.GET("/cloud/v1/report/:tenant/:incident_type/:agg_type/:agg_top", ic.GetReport)
	//log.Fatal(http.ListenAndServe(":8888", router))
	log.Fatal(http.ListenAndServeTLS(":8888", "./certs/server.crt", "./certs/server.key", router))
}
