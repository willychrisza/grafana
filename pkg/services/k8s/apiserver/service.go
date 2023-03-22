package apiserver

import (
	"context"
	"fmt"
	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"
	"net"
	"path"

	"github.com/grafana/dskit/services"
	"github.com/grafana/grafana/pkg/services/certgenerator"
	"github.com/grafana/grafana/pkg/services/k8s/kine"
	"github.com/grafana/grafana/pkg/setting"
	serveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
)

const (
	DEFAULT_IP   = "127.0.0.1"
	DEFAULT_HOST = "https://" + DEFAULT_IP + ":6443"
)

var (
	_ Service            = (*service)(nil)
	_ RestConfigProvider = (*service)(nil)
)

type Service interface {
	services.Service
}

type RestConfigProvider interface {
	GetRestConfig() *rest.Config
}

type service struct {
	*services.BasicService

	etcdProvider kine.EtcdProvider
	restConfig   *rest.Config

	dataPath  string
	stopCh    chan struct{}
	stoppedCh chan error
}

func ProvideService(etcdProvider kine.EtcdProvider, cfg *setting.Cfg) (*service, error) {
	s := &service{
		dataPath:     path.Join(cfg.DataPath, "k8s"),
		etcdProvider: etcdProvider,
		stopCh:       make(chan struct{}),
	}

	s.BasicService = services.NewBasicService(s.start, s.running, nil)

	return s, nil
}

func (s *service) GetRestConfig() *rest.Config {
	return s.restConfig
}

func (s *service) start(ctx context.Context) error {
	serverRunOptions := options.NewServerRunOptions()
	serverRunOptions.ServiceClusterIPRanges = kubeoptions.DefaultServiceIPCIDR.String()
	serverRunOptions.SecureServing.BindAddress = net.ParseIP(DEFAULT_IP)

	err := serverRunOptions.GenericServerRunOptions.DefaultAdvertiseAddress(serverRunOptions.SecureServing.SecureServingOptions)
	if err != nil {
		fmt.Errorf("error getting default advertise address of apiserver for cert generation: %s", err.Error())
		return nil
	}

	serverRunOptions.SecureServing.ServerCert.CertKey = serveroptions.CertKey{
		CertFile: certgenerator.APIServerCertFile,
		KeyFile:  certgenerator.APIServerKeyFile,
	}

	serverRunOptions.Authentication.ServiceAccounts.Issuers = []string{DEFAULT_HOST}
	etcdConfig := s.etcdProvider.GetConfig()
	serverRunOptions.Etcd.StorageConfig.Transport.ServerList = etcdConfig.Endpoints
	serverRunOptions.Etcd.StorageConfig.Transport.CertFile = etcdConfig.TLSConfig.CertFile
	serverRunOptions.Etcd.StorageConfig.Transport.KeyFile = etcdConfig.TLSConfig.KeyFile
	serverRunOptions.Etcd.StorageConfig.Transport.TrustedCAFile = etcdConfig.TLSConfig.CAFile

	completedOptions, err := app.Complete(serverRunOptions)
	if err != nil {
		return err
	}

	server, err := app.CreateServerChain(completedOptions)
	if err != nil {
		return err
	}

	s.restConfig = server.GenericAPIServer.LoopbackClientConfig
	s.restConfig.Host = DEFAULT_HOST
	s.writeKubeConfiguration(s.restConfig)

	prepared, err := server.PrepareRun()
	if err != nil {
		return err
	}

	go func() {
		s.stoppedCh <- prepared.Run(s.stopCh)
	}()

	return nil
}

func (s *service) running(ctx context.Context) error {
	select {
	case err := <-s.stoppedCh:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		close(s.stopCh)
	}
	return nil
}

func (s *service) writeKubeConfiguration(restConfig *rest.Config) error {
	clusters := make(map[string]*clientcmdapi.Cluster)
	clusters["default-cluster"] = &clientcmdapi.Cluster{
		Server:                   restConfig.Host,
		CertificateAuthorityData: restConfig.CAData,
	}

	contexts := make(map[string]*clientcmdapi.Context)
	contexts["default-context"] = &clientcmdapi.Context{
		Cluster:   "default-cluster",
		Namespace: "default",
		AuthInfo:  "default",
	}

	authinfos := make(map[string]*clientcmdapi.AuthInfo)
	authinfos["default"] = &clientcmdapi.AuthInfo{
		Token:    restConfig.BearerToken,
		Username: restConfig.Username,
		Password: restConfig.Password,
	}

	clientConfig := clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		Clusters:       clusters,
		Contexts:       contexts,
		CurrentContext: "default-context",
		AuthInfos:      authinfos,
	}
	return clientcmd.WriteToFile(clientConfig, path.Join(s.dataPath, "grafana.kubeconfig"))
}
