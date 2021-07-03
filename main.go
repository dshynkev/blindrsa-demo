package main

import (
  "encoding/json"
  "encoding/pem"
  "errors"
  "crypto/rsa"
  "crypto/x509"
  "math/big"
  "net/http"
  "log"
  "os"
  "path"
  "strconv"

  "server/rawrsa"
)

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
  b, err := os.ReadFile(path)
  if err != nil {
    return nil, err
  }

  block, rest := pem.Decode(b)
  if len(rest) > 0 {
    return nil, errors.New("trailing PEM data")
  }

  return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func writePublicKey(w http.ResponseWriter, r *http.Request, key *rsa.PublicKey) {
    payload := struct {
      E string `json:"e"`
      N string `json:"n"`
    }{
      strconv.FormatInt(int64(key.E), 16),
      key.N.Text(16),
    }
    json.NewEncoder(w).Encode(&payload)
}

func signMessage(w http.ResponseWriter, r *http.Request, key *rsa.PrivateKey) {
    var in struct {
      M string `json:"m"`
    }
    var out struct {
      S string `json:"s"`
    }

    err := json.NewDecoder(r.Body).Decode(&in)
    defer r.Body.Close()
    if err != nil {
      http.Error(w, "bad request", http.StatusBadRequest)
      return
    }

    m, ok := new(big.Int).SetString(in.M, 16)
    if !ok {
      http.Error(w, "m is not a hex integer", http.StatusBadRequest)
      return
    }
    s, err := rawrsa.Sign(key, m)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    out.S = s.Text(16)
    json.NewEncoder(w).Encode(&out)
}

func main() {
  priv, err := loadRSAPrivateKey("private.pem")
  if err != nil {
    log.Fatal(err)
  }

  http.HandleFunc("/pkey", func(w http.ResponseWriter, r *http.Request) {
    writePublicKey(w, r, &priv.PublicKey)
  })

  http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
    signMessage(w, r, priv)
  })

  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, path.Join("./static", r.URL.Path))
  })

  http.ListenAndServe(":80", nil)
}
