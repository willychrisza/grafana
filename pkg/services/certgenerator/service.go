package certgenerator

import (
	"context"
	"github.com/grafana/dskit/services"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"
)

const (
	DefaultAPIServerIp = "127.0.0.1"
)

var (
	_ Service = (*service)(nil)
)

type Service interface {
	services.Service
}

type service struct {
	*services.BasicService
	certUtil *CertUtil
	Log      log.Logger
}

func ProvideService(cfg *setting.Cfg) (*service, error) {
	certUtil := &CertUtil{}

	s := &service{
		certUtil: certUtil,
		Log:      log.New("certgenerator"),
	}

	s.BasicService = services.NewIdleService(s.up, nil)

	return s, nil
}
func (s *service) up(ctx context.Context) error {
	err := s.certUtil.InitializeCACertPKI()
	if err != nil {
		s.Log.Error("error initializing CA", ctx, err)
	}

	apiServerServiceIP, _, _, err := getServiceIPAndRanges(kubeoptions.DefaultServiceIPCIDR.String())
	if err != nil {
		s.Log.Error("error getting service ip of apiserver for cert generation", err)
		return nil
	}

	s.certUtil.InitializeApiServerPKI(DefaultAPIServerIp, apiServerServiceIP)
	if err != nil {
		s.Log.Error("error initializing API Server cert", ctx, err)
	}

	return nil
}
