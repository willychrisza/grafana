package publicdashboard

import (
	"context"

	"github.com/grafana/grafana/pkg/infra/log"
)

var _ Watcher = (*watcher)(nil)

type watcher struct {
	log log.Logger
}

func ProvideWatcher() (*watcher, error) {
	w := watcher{
		log: log.New("k8s.publicdashboard.watcher"),
	}
	return &w, nil
}

func (w *watcher) Add(ctx context.Context, obj *PublicDashboard) error {
	w.log.Debug("adding PublicDashboard", "obj", obj)
	return nil
}

func (w *watcher) Update(ctx context.Context, oldObj, newObj *PublicDashboard) error {
	w.log.Debug("updating PublicDashboard", "oldObj", oldObj, "newObj", newObj)
	return nil
}

func (w *watcher) Delete(ctx context.Context, obj *PublicDashboard) error {
	w.log.Debug("deleting PublicDashboard", "obj", obj)
	return nil
}
