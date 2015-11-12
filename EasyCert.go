package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"strings"
)

var (
	flagCertificateAuthorityName    = flag.String("cn", "", "")
	flagCertificateAuthorityKeyFile = flag.String("cakey", "", "")
	flagCertificateAuthorityCrtFile = flag.String("cacrt", "", "")
	flagFQDN                        = flag.String("fqdn", "", "")
)

var usage = `Usage: EasyCert [options...]

Options:
  -cn      Certificate Authority Name (can be any name, but should reflect your company name.)
  -cakey   Certificate Authority Key File (use existing CA Key file, can not be used with -cn.)
  -cacrt   Certificate Authority Key File (use existing CA Cer file, can not be used with -cn.)
  -fqdn    Fully qualified domain name of TLS server to install the private cert/key
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage)
	}

	flag.Parse()

	caName := *flagCertificateAuthorityName
	caKeyFile := *flagCertificateAuthorityKeyFile
	caCrtFile := *flagCertificateAuthorityCrtFile
	fqdn := *flagFQDN

	if caKeyFile == "" && caCrtFile == "" && caName == "" && fqdn == "" {
		usageAndExit("No parameters supplied. You must supply -fqdn with either -cn or -cakey & -cacrt")
	}

	if caName != "" && (caKeyFile != "" || caCrtFile != "") {
		usageAndExit("There is no need to supply -cn (certificate authority name) when a -cakey (certificate authority key file) or -cacrt (certificate authority crt file) is already available")
	}

	if caKeyFile == "" && caCrtFile == "" {
		if caName == "" || fqdn == "" {
			usageAndExit("You must supply both a -cn (certificate authority name) and -fqdn (fully qualified domain name) parameter")
		}
	} else if caName == "" {
		if caKeyFile == "" || caCrtFile == "" || fqdn == "" {
			usageAndExit("You must supply a -cakey (certificate authority key file), -cacrt (certificate authority cer file) and -fqdn (fully qualified domain name) parameter")
		}
		if _, err := os.Stat(caKeyFile); os.IsNotExist(err) {
			usageAndExit("The -cakey (certificate authority key file) can not be found")
		}
		if _, err := os.Stat(caCrtFile); os.IsNotExist(err) {
			usageAndExit("The -cactr (certificate authority cer file) can not be found")
		}
	}

	if caKeyFile == "" && caCrtFile == "" {
		caKeyFile, caCrtFile = createPrivateCA(caName)
		log.Println("Private root certificate created: ", caCrtFile)
		log.Println("Private root key created: ", caKeyFile)
	}

	fqdnKeyFile, fqdnCrtFile := createServerCertKey(fqdn, caKeyFile, caCrtFile)
	log.Println("Web server certificate created: ", fqdnCrtFile)
	log.Println("Web server key created: ", fqdnKeyFile)
}

func createPrivateCA(certificateAuthority string) (string, string) {
	caName := strings.Replace(certificateAuthority, ".", "_", -1) + "_CA"
	os.Mkdir(caName, 0700)
	caKeyFile := path.Join(caName, caName+".key")
	caCrtFile := path.Join(caName, caName+".crt")

	_, err := callCommand("openssl", "genrsa", "-out", caKeyFile, "2048")
	if err != nil {
		log.Fatal("Could not create private Certificate Authority key")
	}

	_, err = callCommand("openssl", "req", "-x509", "-new", "-key", caKeyFile, "-sha256", "-extensions", "v3_ca", "-out", caCrtFile, "-days", "7300", "-subj", "/CN=\""+certificateAuthority+"\"")
	if err != nil {
		log.Fatal("Could not create private Certificate Authority certificate")
	}
	return caKeyFile, caCrtFile
}

func createServerCertKey(fqdn, caKeyFile string, caCrtFile string) (string, string) {
	fqdnName := strings.Replace(fqdn, ".", "_", -1)
	os.Mkdir(fqdnName, 0700)
	fqdnKeyFile := path.Join(fqdnName, fqdnName+".key")
	fqdnCrtFile := path.Join(fqdnName, fqdnName+".crt")
	fqdnReqFile := path.Join(fqdnName, fqdnName+".req")

	_, err := callCommand("openssl", "genrsa", "-out", fqdnKeyFile, "2048")
	if err != nil {
		log.Fatal("Could not create private server key")
	}

	_, err = callCommand("openssl", "req", "-sha256", "-new", "-out", fqdnReqFile, "-key", fqdnKeyFile, "-subj", "/CN="+fqdn)
	if err != nil {
		log.Fatal("Could not create private server certificate signing request")
	}

	_, err = callCommand("openssl", "x509", "-sha256", "-req", "-in", fqdnReqFile, "-out", fqdnCrtFile, "-CAkey", caKeyFile, "-CA", caCrtFile, "-days", "7300", "-CAcreateserial", "-CAserial", path.Join(fqdnName, "serial"))
	if err != nil {
		log.Fatal("Could not create private server certificate")
	}
	return fqdnKeyFile, fqdnCrtFile
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
