package modules

import (
	"context"
	"errors"

	"github.com/grafana/dskit/modules"
	"github.com/grafana/dskit/services"

	"github.com/grafana/grafana/pkg/api"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/registry/corecrd"
	"github.com/grafana/grafana/pkg/services/certgenerator"
	"github.com/grafana/grafana/pkg/services/k8s/apiserver"
	"github.com/grafana/grafana/pkg/services/k8s/client"
	"github.com/grafana/grafana/pkg/services/k8s/informer"
	"github.com/grafana/grafana/pkg/services/k8s/kine"
	publicDashboardWebhooks "github.com/grafana/grafana/pkg/services/k8s/resources/publicdashboard/webhooks"
	"github.com/grafana/grafana/pkg/setting"
)

// List of available targets.
const (
	All                 string = "all"
	CertGenerator       string = "cert-generator"
	HTTPServer          string = "http-server"
	Kine                string = "kine"
	KubernetesCRDs      string = "kubernetes-crds"
	KubernetesAPIServer string = "kubernetes-apiserver"
	KubernetesInformers string = "kubernetes-informers"
	KubernetesClientset string = "kubernetes-clientset"
	Kubernetes          string = "kubernetes"

	PublicDashboardWebhooks string = "public-dashboard-webhooks"
)

type Engine interface {
	Init(context.Context) error
	Run(context.Context) error
	Shutdown(context.Context) error
}

type Manager interface {
	RegisterModule(name string, initFn func() (services.Service, error), deps ...string)
	RegisterInvisibleModule(name string, initFn func() (services.Service, error), deps ...string)
}

var _ Engine = (*service)(nil)
var _ Manager = (*service)(nil)

// service manages the registration and lifecycle of modules.
type service struct {
	cfg           *setting.Cfg
	log           log.Logger
	targets       []string
	dependencyMap map[string][]string

	ModuleManager  *modules.Manager
	ServiceManager *services.Manager
	ServiceMap     map[string]services.Service

	publicDashboardWebhooks *publicDashboardWebhooks.WebhooksAPI
	apiServer               apiserver.Service
	certGenerator           certgenerator.Service
	crdRegistry             *corecrd.Registry
	kineService             kine.Service
	intormerService         informer.Service
	clientsetService        client.Service
	httpServer              *api.HTTPServer
}

func ProvideService(
	cfg *setting.Cfg,
	apiServer apiserver.Service,
	certGenerator certgenerator.Service,
	crdRegistry *corecrd.Registry,
	kineService kine.Service,
	informerService informer.Service,
	clientsetService client.Service,
	publicDashboardWebhooks *publicDashboardWebhooks.WebhooksAPI,
	httpServer *api.HTTPServer,
) *service {
	logger := log.New("modules")

	dependencyMap := map[string][]string{
		CertGenerator:           {},
		HTTPServer:              {CertGenerator},
		Kine:                    {},
		KubernetesAPIServer:     {CertGenerator, Kine},
		KubernetesClientset:     {KubernetesAPIServer},
		KubernetesCRDs:          {KubernetesClientset},
		KubernetesInformers:     {KubernetesCRDs},
		Kubernetes:              {KubernetesInformers},
		PublicDashboardWebhooks: {KubernetesClientset},
		All:                     {HTTPServer, Kubernetes, PublicDashboardWebhooks},
	}

	return &service{
		cfg:           cfg,
		log:           logger,
		targets:       cfg.Target,
		dependencyMap: dependencyMap,

		ModuleManager: modules.NewManager(logger),
		ServiceMap:    map[string]services.Service{},

		publicDashboardWebhooks: publicDashboardWebhooks,
		apiServer:               apiServer,
		certGenerator:           certGenerator,
		crdRegistry:             crdRegistry,
		kineService:             kineService,
		intormerService:         informerService,
		clientsetService:        clientsetService,
		httpServer:              httpServer,
	}
}

// Init initializes all registered modules.
func (m *service) Init(_ context.Context) error {
	var err error

	// module registration
	m.RegisterInvisibleModule(HTTPServer, m.httpServerInit)
	m.RegisterModule(CertGenerator, m.certGeneratorInit)
	m.RegisterModule(Kine, m.kineInit)
	m.RegisterModule(KubernetesAPIServer, m.k8sApiServerInit)
	m.RegisterModule(KubernetesClientset, m.k8sClientsetInit)
	m.RegisterModule(KubernetesCRDs, m.k8sCRDsInit)
	m.RegisterModule(KubernetesInformers, m.k8sInformersInit)
	m.RegisterModule(PublicDashboardWebhooks, m.publicDashboardWebhooksInit)
	m.RegisterModule(Kubernetes, nil)
	m.RegisterModule(All, nil)

	for mod, targets := range m.dependencyMap {
		if err := m.ModuleManager.AddDependency(mod, targets...); err != nil {
			return err
		}
	}

	m.ServiceMap, err = m.ModuleManager.InitModuleServices(m.targets...)
	if err != nil {
		return err
	}

	// if no modules are registered, we don't need to start the service manager
	if len(m.ServiceMap) == 0 {
		return nil
	}

	var svcs []services.Service
	for _, s := range m.ServiceMap {
		svcs = append(svcs, s)
	}
	m.ServiceManager, err = services.NewManager(svcs...)

	return err
}

// Run starts all registered modules.
func (m *service) Run(ctx context.Context) error {
	// we don't need to continue if no modules are registered.
	// this behavior may need to change if dskit services replace the
	// current background service registry.
	if len(m.ServiceMap) == 0 {
		m.log.Warn("No modules registered...")
		<-ctx.Done()
		return nil
	}

	listener := newServiceListener(m.log, m)
	m.ServiceManager.AddListener(listener)

	// wait until a service fails or stop signal was received
	err := m.ServiceManager.StartAsync(ctx)
	if err != nil {
		return err
	}

	err = m.ServiceManager.AwaitStopped(ctx)
	if err != nil {
		return err
	}

	failed := m.ServiceManager.ServicesByState()[services.Failed]
	for _, f := range failed {
		// the service listener will log error details for all modules that failed,
		// so here we return the first error that is not ErrStopProcess
		if !errors.Is(f.FailureCase(), modules.ErrStopProcess) {
			return f.FailureCase()
		}
	}

	return nil
}

// Shutdown stops all modules and waits for them to stop.
func (m *service) Shutdown(ctx context.Context) error {
	if m.ServiceManager == nil {
		m.log.Debug("No modules registered, nothing to stop...")
		return nil
	}
	m.ServiceManager.StopAsync()
	m.log.Info("Awaiting services to be stopped...")
	return m.ServiceManager.AwaitStopped(ctx)
}

// RegisterModule registers a module with the dskit module manager.
func (m *service) RegisterModule(name string, initFn func() (services.Service, error), deps ...string) {
	m.ModuleManager.RegisterModule(name, initFn)
	if len(deps) == 0 {
		return
	}
	m.dependencyMap[name] = deps
}

// RegisterInvisibleModule registers an invisible module with the dskit module manager.
// Invisible modules are not visible to the user, and are intendent to be used as dependencies.
func (m *service) RegisterInvisibleModule(name string, initFn func() (services.Service, error), deps ...string) {
	m.ModuleManager.RegisterModule(name, initFn, modules.UserInvisibleModule)
	if len(deps) == 0 {
		return
	}
	m.dependencyMap[name] = deps
}

// IsModuleEnabled returns true if the module is enabled.
func (m *service) IsModuleEnabled(name string) bool {
	return stringsContain(m.targets, name)
}

func (m *service) certGeneratorInit() (services.Service, error) {
	return m.certGenerator, nil
}

func (m *service) k8sApiServerInit() (services.Service, error) {
	return m.apiServer, nil
}

func (m *service) k8sCRDsInit() (services.Service, error) {
	return m.crdRegistry, nil
}

func (m *service) k8sInformersInit() (services.Service, error) {
	return m.intormerService, nil
}

func (m *service) k8sClientsetInit() (services.Service, error) {
	return m.clientsetService, nil
}

func (m *service) kineInit() (services.Service, error) {
	return m.kineService, nil
}

func (m *service) publicDashboardWebhooksInit() (services.Service, error) {
	return m.publicDashboardWebhooks, nil
}

func (m *service) httpServerInit() (services.Service, error) {
	return m.httpServer, nil
}
