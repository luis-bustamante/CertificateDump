# CertificateDump

Dump the certificate received by the server.

Details:
  1. The client makes a https request
  2. The server requests the client certificate
  3. The server dumps the certificate data to the log output
  

How to run:
Compile the server.go on an separate folder because the client.go provides repeated functions that will throw a compile error. Client.go is just a client example. The only required file is the server.go.
