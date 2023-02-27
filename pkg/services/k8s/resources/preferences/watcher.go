package preferences

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
		log: log.New("k8s.preferences.watcher"),
	}
	return &w, nil
}

func (w *watcher) Add(ctx context.Context, obj *Preferences) error {
	w.log.Debug("adding Preferences", "obj", obj)
	return nil
}

func (w *watcher) Update(ctx context.Context, oldObj, newObj *Preferences) error {
	w.log.Debug("updating Preferences", "oldObj", oldObj, "newObj", newObj)
	return nil
}

func (w *watcher) Delete(ctx context.Context, obj *Preferences) error {
	w.log.Debug("deleting Preferences", "obj", obj)
	return nil
}
