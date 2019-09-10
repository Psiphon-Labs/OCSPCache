package main

import (
    "net/http"
    "log"
)

func Server(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("This is an example server.\n"))
}

func main() {
    http.HandleFunc("/", Server)
    err := http.ListenAndServeTLS(":8083", 
                                  "./CA/cert_chain.pem", 
                                  "./CA/intermediate/enduser-certs/local_ocsp_urls.key", 
                                  nil)
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}

