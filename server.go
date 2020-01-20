package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	log.Println("HTTP request dump:")
	log.Println(string(dump))
	if err != nil{
		log.Println("HTTP request error:")
		log.Println(err)
	}
	log.Println("HTTP TLS:")
	tls := r.TLS
	log.Println("Version ", tls.Version)       				//uint16 				// TLS version used by the connection (e.g. VersionTLS12)
	log.Println("HandshakeComplete ", tls.HandshakeComplete)   //bool                  // TLS handshake is complete
	log.Println("DidResume ", tls.DidResume)                   //bool                  // connection resumes a previous TLS connection
	log.Println("CipherSuite ", tls.CipherSuite)               //uint16                // cipher suite in use (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ...)
	log.Println("NegotiatedProtocol ", tls.NegotiatedProtocol) //string                // negotiated next protocol (not guaranteed to be from Config.NextProtos)
	log.Println("NegotiatedProtocolIsMutual ", tls.NegotiatedProtocolIsMutual) //bool                  // negotiated protocol was advertised by server (client side only)
	log.Println("ServerName ", tls.ServerName) //                  string                // server name requested by client, if any (server side only)
	log.Println("PeerCertificates ", tls.PeerCertificates)//            []*x509.Certificate   // certificate chain presented by remote peer
	log.Println("VerifiedChains ", tls.VerifiedChains)//[][]*x509.Certificate // verified chains built from PeerCertificates
	log.Println("SignedCertificateTimestamps ", tls.SignedCertificateTimestamps) // [][]byte              // SCTs from the peer, if any
	log.Println("OCSPResponse ", tls.OCSPResponse) //                []byte                // stapled OCSP response from peer, if any
	log.Println("TLSUnique ", string(tls.TLSUnique))

	if len(tls.PeerCertificates) > 0{
		log.Println("HTTP CERTS:")
		for k, cert := range tls.PeerCertificates {
			log.Println("Cert ", k)
			log.Println("Raw ", cert.Raw)//                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
			log.Println("RawTBSCertificate ", cert.RawTBSCertificate)//        []byte // Certificate part of raw ASN.1 DER content.
			log.Println("RawSubjectPublicKeyInfo ", cert.RawSubjectPublicKeyInfo)// []byte // DER encoded SubjectPublicKeyInfo.
			log.Println("RawSubject ", cert.RawSubject)//[]byte // DER encoded Subject
			log.Println("RawIssuer ", cert.RawIssuer)//[]byte // DER encoded Issuer
			log.Println("Signature ", cert.Signature)//[]byte
			log.Println("SignatureAlgorithm ", cert.SignatureAlgorithm)//SignatureAlgorithm
			log.Println("PublicKeyAlgorithm ", cert.PublicKeyAlgorithm)//PublicKeyAlgorithm
			log.Println("PublicKey ", cert.PublicKey)//interface{}
			log.Println("Version ", cert.Version)//int
			log.Println("SerialNumber ", cert.SerialNumber)//*big.Int
			log.Println("Issuer ", cert.Issuer)//pkix.Name
			log.Println("Subject ", cert.Subject)//pkix.Name
			log.Println("NotBefore ", cert.NotBefore)
			log.Println("NotAfter ", cert.NotAfter )//time.Time // Validity bounds.
			log.Println("KeyUsage ", cert.KeyUsage )//KeyUsage
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	//cert generation
	genCert := false
	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		genCert = true
	}
	if _, err := os.Stat("key.pem"); os.IsNotExist(err) {
		genCert = true
	}
	if genCert {
		GetNewSSLCert()
	}
	//end of cert generation

	http.HandleFunc("/", defaultHandler)
	server := &http.Server{
		Addr: "localhost:8088",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
		},
	}
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil{
		log.Println(err.Error())
	}
}

func GetNewSSLCert() {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)

	subject := pkix.Name{
		Organization:       []string{"Organization-X"},
		OrganizationalUnit: []string{"Organization-XU"},
		CommonName:         "Common Organization",
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)

	certOut, _ := os.Create("cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.Create("key.pem")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	keyOut.Close()
}