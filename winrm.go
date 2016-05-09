/*
Copyright 2013 Brice Figureau

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/core/http"
	"github.com/Azure/azure-sdk-for-go/core/tls"

	"github.com/masterzen/winrm/soap"
	"github.com/masterzen/winrm/winrm"
)

func main() {
	var (
		hostname string
		user     string
		pass     string
		cmd      string
		port     int
		https    bool
		insecure bool
		cacert   string
		cert     string
		key      string
	)

	flag.StringVar(&hostname, "hostname", "localhost", "winrm host")
	flag.StringVar(&user, "username", "vagrant", "winrm admin username")
	flag.StringVar(&pass, "password", "vagrant", "winrm admin password")
	flag.IntVar(&port, "port", 5985, "winrm port")
	flag.BoolVar(&https, "https", false, "use https")
	flag.BoolVar(&insecure, "insecure", false, "skip SSL validation")
	flag.StringVar(&cacert, "cacert", "", "CA certificate to use")
	flag.StringVar(&cert, "cert", "", "Cert")
	flag.StringVar(&key, "key", "", "Key")

	flag.Parse()

	var err error
	var certBytes, keyBytes []byte
	if cert != "" && key != "" {
		certBytes, err = ioutil.ReadFile(cert)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		keyBytes, err = ioutil.ReadFile(key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		certBytes = nil
		keyBytes = nil
	}

	var cacertBytes []byte
	if cacert != "" {
		cacertBytes, err = ioutil.ReadFile(cacert)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		cacertBytes = nil
	}

	if cert != "" && key != "" {
		endpoint := &winrm.Endpoint{Host: hostname, Port: port, HTTPS: https, Insecure: insecure, CACert: &cacertBytes, Cert: &certBytes, Key: &keyBytes}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: endpoint.Insecure,
			},
		}

		// Missing CA Certs
		certPool, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			fmt.Println("Error parsing keypair")
			os.Exit(1)
		}

		transport.TLSClientConfig.Certificates = []tls.Certificate{certPool}

		var soapXML string = "application/soap+xml"
		body := func(response *http.Response) (content string, err error) {
			contentType := response.Header.Get("Content-Type")
			if strings.HasPrefix(contentType, soapXML) {
				var body []byte
				body, err = ioutil.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					err = fmt.Errorf("error while reading request body %s", err)
					return
				}

				content = string(body)
				return
			} else {
				err = fmt.Errorf("invalid content-type: %s", contentType)
				return
			}
		}

		post := func(client *winrm.Client, request *soap.SoapMessage) (response string, err error) {
			// transport is the one we created above, it needs to be passed in like this and not with a parameter
			httpClient := &http.Client{Transport: transport}

			req, err := http.NewRequest("POST", client.URL(), strings.NewReader(request.String()))
			if err != nil {
				err = fmt.Errorf("impossible to create http request %s", err)
				return
			}
			req.Header.Set("Content-Type", soapXML+";charset=UTF-8")

			req.Header.Add("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual")

			resp, err := httpClient.Do(req)
			if err != nil {
				err = fmt.Errorf("unknown error %s", err)
				return
			}

			if resp.StatusCode == 200 {
				response, err = body(resp)
			} else {
				body, _ := ioutil.ReadAll(resp.Body)
				err = fmt.Errorf("http error: %d - %s", resp.StatusCode, body)
			}

			return
		}

		cmd = flag.Arg(0)
		client, err := winrm.NewClientWithCertificate(endpoint, winrm.DefaultParameters(), post)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		exitCode, err := client.RunWithInput(cmd, os.Stdout, os.Stderr, os.Stdin)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		os.Exit(exitCode)
	}

	cmd = flag.Arg(0)
	client, err := winrm.NewClient(&winrm.Endpoint{Host: hostname, Port: port, HTTPS: https, Insecure: insecure, CACert: &cacertBytes, Cert: &certBytes, Key: &keyBytes}, user, pass)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	exitCode, err := client.RunWithInput(cmd, os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}
