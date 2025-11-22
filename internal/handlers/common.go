package handlers

import "net/http"

type Handler interface {
	Handle(w http.ResponseWriter, r *http.Request)
}

func Wrap(h Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Handle(w, r)
	})
}
