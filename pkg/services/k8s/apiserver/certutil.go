package apiserver

import (
	"fmt"
	serveroptions "k8s.io/apiserver/pkg/server/options"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/pkg/controlplane"
	netutils "k8s.io/utils/net"
	"net"
	"strings"
)

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

func newApiServerCertKey(advertiseAddress string, alternativeIP net.IP) (*serveroptions.CertKey, error) {
	serverTLSCertFile := "data/k8s/apiserver.crt"
	serverTLSKeyFile := "data/k8s/apiserver.key"
	tokenSigningCertExists, _ := certutil.CanReadCertAndKey(serverTLSCertFile, serverTLSCertFile)
	if tokenSigningCertExists == false {
		cert, key, err := certutil.GenerateSelfSignedCertKey(advertiseAddress, []net.IP{alternativeIP}, []string{"kubernetes.default.svc", "kubernetes.default", "kubernetes"})
		if err != nil {
			fmt.Println("Error generating apiserver TLS cert")
			return nil, err
		} else {
			certutil.WriteCert(serverTLSCertFile, cert)
			keyutil.WriteKey(serverTLSKeyFile, key)
		}
	}

	return &serveroptions.CertKey{
		CertFile: serverTLSCertFile,
		KeyFile:  serverTLSKeyFile,
	}, nil
}
