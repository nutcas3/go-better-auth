package router

import (
	"net/http"
	"strings"
)

type Router struct {
	routes []route
}

type route struct {
	method  string
	path    string
	handler http.Handler
}

func New() *Router {
	return &Router{}
}

func (r *Router) Handle(method, path string, handler http.Handler) {
	r.routes = append(r.routes, route{
		method:  method,
		path:    path,
		handler: handler,
	})
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	for _, rt := range r.routes {
		if rt.method != "*" && req.Method != rt.method {
			continue
		}

		if match(rt.path, req.URL.Path) {
			rt.handler.ServeHTTP(w, req)
			return
		}
	}
	http.NotFound(w, req)
}

func match(route, path string) bool {
	if route == path {
		return true
	}

	if strings.HasSuffix(route, "/*") {
		prefix := strings.TrimSuffix(route, "/*")
		return strings.HasPrefix(path, prefix)
	}

	return false
}
