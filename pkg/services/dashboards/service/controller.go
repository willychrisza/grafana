package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/grafana/grafana/pkg/apimachinery/bridge"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/kinds/dashboard"
	"github.com/grafana/grafana/pkg/kindsys/k8ssys"
	"github.com/grafana/grafana/pkg/registry/corecrd"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

type DashboardController struct {
	cfg              *setting.Cfg
	dashboardService *DashboardServiceImpl
	bridgeService    *bridge.Service
	reg              *corecrd.Registry
}

func ProvideDashboardController(cfg *setting.Cfg, bridgeService *bridge.Service, reg *corecrd.Registry, dasboardService *DashboardServiceImpl) *DashboardController {
	return &DashboardController{
		cfg:              cfg,
		dashboardService: dasboardService,
		bridgeService:    bridgeService,
		reg:              reg,
	}
}

func (c *DashboardController) Run(ctx context.Context) error {
	dashboardCRD := c.reg.Dashboard()

	gvr := schema.GroupVersionResource{
		Group:    dashboardCRD.GVK().Group,
		Version:  dashboardCRD.GVK().Version,
		Resource: dashboardCRD.Schema.Spec.Names.Plural,
	}

	factory := dynamicinformer.NewDynamicSharedInformerFactory(c.bridgeService.ClientSet.Dynamic, time.Minute)
	dashboardInformer := factory.ForResource(gvr).Informer()

	dashboardInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dash, err := interfaceToK8sDashboard(obj)
			if err != nil {
				fmt.Println("dashboard add failed", err)
				return
			}

			dto := k8sDashboardToDashboardDTO(dash)
			if existing, err := c.dashboardService.GetDashboard(context.Background(), &dashboards.GetDashboardQuery{UID: dto.Dashboard.UID, OrgID: dto.OrgID}); err == nil && existing.Version >= dto.Dashboard.Version {
				fmt.Println("dashboard already exists, skipping")
				return
			}
			_, err = c.dashboardService.SaveDashboard(context.Background(), dto, false)
			if err != nil {
				fmt.Println("dashboardService.SaveDashboard failed", err)
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dash, err := interfaceToK8sDashboard(newObj)
			if err != nil {
				fmt.Println("dashboard add failed", err)
				return
			}

			dto := k8sDashboardToDashboardDTO(dash)
			if existing, err := c.dashboardService.GetDashboard(context.Background(), &dashboards.GetDashboardQuery{UID: dto.Dashboard.UID, OrgID: dto.OrgID}); err == nil && existing.Version >= dto.Dashboard.Version {
				fmt.Println("dashboard version already exists, skipping")
				return
			}
			_, err = c.dashboardService.SaveDashboard(context.Background(), dto, false)
			if err != nil {
				fmt.Println("dashboardService.SaveDashboard failed", err)
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			dash, err := interfaceToK8sDashboard(obj)
			if err != nil {
				fmt.Println("dashboard delete", err)
				return
			}

			fmt.Printf("dashboard deleted: %+v \n", dash)
			//c.dashboardService.DeleteDashboard(ctx, obj.ID, obj.OrgID)
		},
	})

	stop := make(chan struct{})
	defer close(stop)

	factory.Start(stop)
	<-ctx.Done()
	return nil
}

func (c *DashboardController) IsDisabled() bool {
	return !c.cfg.IsFeatureToggleEnabled(featuremgmt.FlagApiserver)
}
func interfaceToK8sDashboard(obj interface{}) (*k8ssys.Base[dashboard.Dashboard], error) {
	uObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("failed to convert interface{} to *unstructured.Unstructured")
	}

	dash := k8ssys.Base[dashboard.Dashboard]{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(uObj.UnstructuredContent(), &dash)
	if err != nil {
		return nil, fmt.Errorf("failed to convert *unstructured.Unstructured to *k8ssys.Base[dashboard.Dashboard]")
	}
	return &dash, nil
}

func k8sDashboardToDashboardDTO(dash *k8ssys.Base[dashboard.Dashboard]) *dashboards.SaveDashboardDTO {
	data := simplejson.NewFromAny(dash.Spec)
	dto := dashboards.SaveDashboardDTO{
		Dashboard: &dashboards.Dashboard{
			FolderID: 1,
			IsFolder: false,
			Data:     data,
		},
	}
	if dash.Spec.Id != nil {
		dto.Dashboard.ID = *dash.Spec.Id
	}
	if dash.Spec.Uid != nil {
		dto.Dashboard.UID = *dash.Spec.Uid
	}
	if dash.Spec.Title != nil {
		dto.Dashboard.Title = *dash.Spec.Title
	}
	if dash.Spec.Version != nil {
		dto.Dashboard.Version = *dash.Spec.Version
	}
	if dash.Spec.GnetId != nil {
		gnetId, err := strconv.ParseInt(*dash.Spec.GnetId, 10, 64)
		if err == nil {
			dto.Dashboard.GnetID = gnetId
		}
	}

	dto = parseAnnotations(dash, dto)
	dto = parseLabels(dash, dto)

	return &dto
}

func parseAnnotations(dash *k8ssys.Base[dashboard.Dashboard], dto dashboards.SaveDashboardDTO) dashboards.SaveDashboardDTO {
	if dash.ObjectMeta.Annotations == nil {
		return dto
	}
	a := dash.ObjectMeta.Annotations
	if v, ok := a["message"]; ok {
		dto.Message = v
	}

	if v, ok := a["orgID"]; ok {
		orgID, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			dto.OrgID = orgID
		}
	}

	if v, ok := a["overwrite"]; ok {
		overwrite, err := strconv.ParseBool(v)
		if err == nil {
			dto.Overwrite = overwrite
		}
	}

	if v, ok := a["updatedBy"]; ok {
		updatedBy, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			dto.Dashboard.UpdatedBy = updatedBy
		}
	}

	if v, ok := a["updatedAt"]; ok {
		updatedAt, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			dto.Dashboard.Updated = time.Unix(0, updatedAt)
		}
	}

	if v, ok := a["createdBy"]; ok {
		createdBy, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			dto.Dashboard.CreatedBy = createdBy
		}
	}

	if v, ok := a["createdAt"]; ok {
		createdAt, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			dto.Dashboard.Created = time.Unix(0, createdAt)
		}
	}

	if v, ok := a["folderId"]; ok {
		folderId, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			dto.Dashboard.FolderID = folderId
		}
	}

	if v, ok := a["isFolder"]; ok {
		isFolder, err := strconv.ParseBool(v)
		if err == nil {
			dto.Dashboard.IsFolder = isFolder
		}
	}

	return dto
}

func parseLabels(dash *k8ssys.Base[dashboard.Dashboard], dto dashboards.SaveDashboardDTO) dashboards.SaveDashboardDTO {
	if dash.ObjectMeta.Labels == nil {
		return dto
	}
	l := dash.ObjectMeta.Labels

	if v, ok := l["slug"]; ok {
		dto.Dashboard.Slug = v
	}
	if v, ok := l["title"]; ok {
		dto.Dashboard.Title = v
	}

	return dto
}