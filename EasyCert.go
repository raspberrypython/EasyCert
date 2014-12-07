package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
)

var (
	flagCertificateAuthorityName = flag.String("cn", "", "")
	flagCertificateAuthorityFile = flag.String("cf", "", "")
	flagHostName                 = flag.String("h", "", "")
)

var usage = `Usage: EasyCert [options...]

Options:
  -cn Certificate Authority Name (can be any name, but should reflect your company name.)
  -cf Certificate Authority File (use existing CA file, can not be used with -cn.)
  -h  Hostname of TLS server to install the private cert/key
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage)
	}

	flag.Parse()

	certName := *flagCertificateAuthorityName
	certFile := *flagCertificateAuthorityFile
	hostName := *flagHostName

	if certName != "" && certFile != "" {
		usageAndExit("There is no need to supply -cn (certificate name) when a -cf (certificate file) is already available")
	}

	if certFile == "" {
		if certName == "" || hostName == "" {
			usageAndExit("You must supply both a -cn (certificate name) and -h (host name) parameter")
		}
	} else if certName == "" {
		if certFile == "" || hostName == "" {
			usageAndExit("You must supply both a -cf (certificate file) and -h (host name) parameter")
		}
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			usageAndExit("The -cf (certificate file) can not be found")
		}
	}

	if certFile == "" {
		certFile := createPrivateCA(certName)
		log.Println("Private root certificate created: ", certFile+".cer")
	}

	hostFile := createServerCertKey(hostName, certFile)
	log.Println("Web server certificate created: ", hostFile+".cer")
	log.Println("Web server key created: ", hostFile+".key")
}

func createPrivateCA(certificateAuthorityName string) string {
	certificateAuthorityFile := strings.Replace(certificateAuthorityName, ".", "_", -1) + "_CA"
	_, err := callCommand("openssl", "genrsa", "-out", certificateAuthorityFile+".key", "2048")
	if err != nil {
		log.Fatal("Could not create private Certificate Authority key")
	}

	_, err = callCommand("openssl", "req", "-x509", "-new", "-key", certificateAuthorityFile+".key", "-out", certificateAuthorityFile+".cer", "-days", "730", "-subj", "/CN=\""+certificateAuthorityName+"\"")
	if err != nil {
		log.Fatal("Could not create private Certificate Authority certificate")
	}
	return certificateAuthorityFile
}

func createServerCertKey(host, certFile string) string {
	hostFile := strings.Replace(host, ".", "_", -1)
	_, err := callCommand("openssl", "genrsa", "-out", hostFile+".key", "2048")
	if err != nil {
		log.Fatal("Could not create private server key")
	}

	_, err = callCommand("openssl", "req", "-new", "-out", hostFile+".req", "-key", hostFile+".key", "-subj", "/CN="+host)
	if err != nil {
		log.Fatal("Could not create private server certificate signing request")
	}

	_, err = callCommand("openssl", "x509", "-req", "-in", hostFile+".req", "-out", hostFile+".cer", "-CAkey", certFile+".key", "-CA", certFile+".cer", "-days", "365", "-CAcreateserial", "-CAserial", "serial")
	if err != nil {
		log.Fatal("Could not create private server certificate")
	}
	return hostFile
}

func callCommand(command string, arg ...string) (string, error) {
	out, err := exec.Command(command, arg...).Output()

	if err != nil {
		log.Println("callCommand failed!")
		log.Println("")
		log.Println(string(debug.Stack()))
		return "", err
	}
	return string(out), nil
}

func usageAndExit(message string) {
	if message != "" {
		fmt.Fprintf(os.Stderr, message)
		fmt.Fprintf(os.Stderr, "\n\n")
	}
	flag.Usage()
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}
