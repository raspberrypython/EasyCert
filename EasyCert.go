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
	flagCertificateAuthorityCerFile = flag.String("cacer", "", "")
	flagFQDN                        = flag.String("fqdn", "", "")
)

var usage = `Usage: EasyCert [options...]

Options:
  -cn      Certificate Authority Name (can be any name, but should reflect your company name.)
  -cakey   Certificate Authority Key File (use existing CA Key file, can not be used with -cn.)
  -cacer   Certificate Authority Key File (use existing CA Cer file, can not be used with -cn.)
  -fqdn    Fully qualified domain name of TLS server to install the private cert/key
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage)
	}

	flag.Parse()

	caName := *flagCertificateAuthorityName
	caKeyFile := *flagCertificateAuthorityKeyFile
	caCerFile := *flagCertificateAuthorityCerFile
	fqdn := *flagFQDN

	if caName != "" && (caKeyFile != "" || caCerFile != "") {
		usageAndExit("There is no need to supply -cn (certificate authority name) when a -cakey (certificate authority key file) or -cacer (certificate authority cer file) is already available")
	}

	if caKeyFile == "" && caCerFile == "" {
		if caName == "" || fqdn == "" {
			usageAndExit("You must supply both a -cn (certificate authority name) and -fqdn (fully qualified domain name) parameter")
		}
	} else if caName == "" {
		if caKeyFile == "" || caCerFile == "" || fqdn == "" {
			usageAndExit("You must supply a -cakey (certificate authority key file), -cacer (certificate authority cer file) and -fqdn (fully qualified domain name) parameter")
		}
		if _, err := os.Stat(caKeyFile); os.IsNotExist(err) {
			usageAndExit("The -cakey (certificate authority key file) can not be found")
		}
		if _, err := os.Stat(caCerFile); os.IsNotExist(err) {
			usageAndExit("The -cacer (certificate authority cer file) can not be found")
		}
	}

	if caKeyFile == "" && caCerFile == "" {
		caKeyFile, caCerFile = createPrivateCA(caName)
		log.Println("Private root certificate created: ", caCerFile)
		log.Println("Private root key created: ", caKeyFile)
	}

	fqdnKeyFile, fqdnCerFile := createServerCertKey(fqdn, caKeyFile, caCerFile)
	log.Println("Web server certificate created: ", fqdnCerFile)
	log.Println("Web server key created: ", fqdnKeyFile)
}

func createPrivateCA(certificateAuthority string) (string, string) {
	caName := strings.Replace(certificateAuthority, ".", "_", -1) + "_CA"
	os.Mkdir(caName, 0700)
	caKeyFile := path.Join(caName, caName+".key")
	caCerFile := path.Join(caName, caName+".cer")

	_, err := callCommand("openssl", "genrsa", "-out", caKeyFile, "2048")
	if err != nil {
		log.Fatal("Could not create private Certificate Authority key")
	}

	_, err = callCommand("openssl", "req", "-x509", "-new", "-key", caKeyFile, "-out", caCerFile, "-days", "730", "-subj", "/CN=\""+certificateAuthority+"\"")
	if err != nil {
		log.Fatal("Could not create private Certificate Authority certificate")
	}
	return caKeyFile, caCerFile
}

func createServerCertKey(fqdn, caKeyFile string, caCerFile string) (string, string) {
	fqdnName := strings.Replace(fqdn, ".", "_", -1)
	os.Mkdir(fqdnName, 0700)
	fqdnKeyFile := path.Join(fqdnName, fqdnName+".key")
	fqdnCerFile := path.Join(fqdnName, fqdnName+".cer")
	fqdnReqFile := path.Join(fqdnName, fqdnName+".req")

	_, err := callCommand("openssl", "genrsa", "-out", fqdnKeyFile, "2048")
	if err != nil {
		log.Fatal("Could not create private server key")
	}

	_, err = callCommand("openssl", "req", "-new", "-out", fqdnReqFile, "-key", fqdnKeyFile, "-subj", "/CN="+fqdn)
	if err != nil {
		log.Fatal("Could not create private server certificate signing request")
	}

	_, err = callCommand("openssl", "x509", "-req", "-in", fqdnReqFile, "-out", fqdnCerFile, "-CAkey", caKeyFile, "-CA", caCerFile, "-days", "365", "-CAcreateserial", "-CAserial", path.Join(fqdnName, "serial"))
	if err != nil {
		log.Fatal("Could not create private server certificate")
	}
	return fqdnKeyFile, fqdnCerFile
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
