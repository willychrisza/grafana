package certgenerator

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/pkg/controlplane"
	netutils "k8s.io/utils/net"
	"net"
	"strings"
)

const (
	CACertFile = "data/k8s/ca.crt"
	CAKeyFile  = "data/k8s/ca.key"

	APIServerCertFile = "data/k8s/apiserver.crt"
	APIServerKeyFile  = "data/k8s/apiserver.key"
)

type CertUtil struct {
	caKey  *rsa.PrivateKey
	caCert *x509.Certificate
}

// Lifted from apiserver package as it's a dependency of external cert generation
func getServiceIPAndRanges(serviceClusterIPRanges string) (net.IP, net.IPNet, net.IPNet, error) {
	serviceClusterIPRangeList := make([]string, 0)
	if serviceClusterIPRanges != "" {
		serviceClusterIPRangeList = strings.Split(serviceClusterIPRanges, ",")
	}

	var apiServerServiceIP net.IP
	var primaryServiceIPRange net.IPNet
	var secondaryServiceIPRange net.IPNet
	var err error
	// nothing provided by user, use default range (only applies to the Primary)
	if len(serviceClusterIPRangeList) == 0 {
		var primaryServiceClusterCIDR net.IPNet
		primaryServiceIPRange, apiServerServiceIP, err = controlplane.ServiceIPRange(primaryServiceClusterCIDR)
		if err != nil {
			return net.IP{}, net.IPNet{}, net.IPNet{}, fmt.Errorf("error determining service IP ranges: %v", err)
		}
		return apiServerServiceIP, primaryServiceIPRange, net.IPNet{}, nil
	}

	_, primaryServiceClusterCIDR, err := netutils.ParseCIDRSloppy(serviceClusterIPRangeList[0])
	if err != nil {
		return net.IP{}, net.IPNet{}, net.IPNet{}, fmt.Errorf("service-cluster-ip-range[0] is not a valid cidr")
	}

	primaryServiceIPRange, apiServerServiceIP, err = controlplane.ServiceIPRange(*primaryServiceClusterCIDR)
	if err != nil {
		return net.IP{}, net.IPNet{}, net.IPNet{}, fmt.Errorf("error determining service IP ranges for primary service cidr: %v", err)
	}

	// user provided at least two entries
	// note: validation asserts that the list is max of two dual stack entries
	if len(serviceClusterIPRangeList) > 1 {
		_, secondaryServiceClusterCIDR, err := netutils.ParseCIDRSloppy(serviceClusterIPRangeList[1])
		if err != nil {
			return net.IP{}, net.IPNet{}, net.IPNet{}, fmt.Errorf("service-cluster-ip-range[1] is not an ip net")
		}
		secondaryServiceIPRange = *secondaryServiceClusterCIDR
	}
	return apiServerServiceIP, primaryServiceIPRange, secondaryServiceIPRange, nil
}

func (cg *CertUtil) InitializeCACertPKI() error {
	caKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)

	if err != nil {
		return err
	}

	caCert, err := certutil.NewSelfSignedCACert(certutil.Config{
		CommonName:   "embedded-apiserver-ca",
		Organization: []string{"Grafana Labs"},
		AltNames: certutil.AltNames{
			DNSNames: []string{"Grafana Embedded API Server CA"},
		},
	}, caKey)

	if err != nil {
		return nil
	}

	cg.caCert = caCert
	cg.caKey = caKey

	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(cg.caKey)}); err != nil {
		return err
	}

	err = certutil.WriteCert(CACertFile, cg.caCert.Raw)
	if err != nil {
		fmt.Errorf("error persisting CA Cert: %s", err.Error())
		return err
	}
	err = keyutil.WriteKey(CAKeyFile, keyBuffer.Bytes())
	if err != nil {
		fmt.Errorf("error persisting CA Key: %s", err.Error())
		return err
	}

	return nil
}

func (cg *CertUtil) InitializeApiServerPKI(advertiseAddress string, alternateIP net.IP) error {
	validFrom := time.Now().Add(-time.Hour) // valid an hour earlier to avoid flakes due to clock skew
	maxAge := time.Hour * 24 * 365          // one year self-signed certs
	alternateIPs := []net.IP{alternateIP}
	alternateDNS := []string{"kubernetes.default.svc", "kubernetes.default", "kubernetes"}

	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s@%d", advertiseAddress, time.Now().Unix()),
		},
		NotBefore: validFrom,
		NotAfter:  validFrom.Add(maxAge),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := netutils.ParseIPSloppy(advertiseAddress); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, advertiseAddress)
	}

	template.IPAddresses = append(template.IPAddresses, alternateIPs...)
	template.DNSNames = append(template.DNSNames, alternateDNS...)

	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, cg.caCert, &priv.PublicKey, cg.caKey)
	if err != nil {
		return err
	}

	// Generate cert, followed by ca
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: certutil.CertificateBlockType, Bytes: derBytes}); err != nil {
		return err
	}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: certutil.CertificateBlockType, Bytes: cg.caCert.Raw}); err != nil {
		return err
	}

	// Generate key
	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	err = certutil.WriteCert(APIServerCertFile, certBuffer.Bytes())
	if err != nil {
		fmt.Errorf("error persisting API Server Cert: %s", err.Error())
		return err
	}

	err = keyutil.WriteKey(APIServerKeyFile, keyBuffer.Bytes())
	if err != nil {
		fmt.Errorf("error persisting API Server Key: %s", err.Error())
		return err
	}

	return nil
}
