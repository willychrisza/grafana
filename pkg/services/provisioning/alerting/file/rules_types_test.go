package file

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/provisioning/values"
)

func TestRuleGroup(t *testing.T) {
	t.Run("a valid rule group should not error", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		_, err := rg.MapToModel()
		require.NoError(t, err)
	})
	t.Run("a rule group with out a name should error", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		var name values.StringValue
		err := yaml.Unmarshal([]byte(""), &name)
		require.NoError(t, err)
		rg.Name = name
		_, err = rg.MapToModel()
		require.Error(t, err)
	})
	t.Run("a rule group with out a folder should error", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		var folder values.StringValue
		err := yaml.Unmarshal([]byte(""), &folder)
		require.NoError(t, err)
		rg.Folder = folder
		_, err = rg.MapToModel()
		require.Error(t, err)
	})
	t.Run("a rule group with out an interval should error", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		var interval values.StringValue
		err := yaml.Unmarshal([]byte(""), &interval)
		require.NoError(t, err)
		rg.Interval = interval
		_, err = rg.MapToModel()
		require.Error(t, err)
	})
	t.Run("a rule group with an invalid interval should error", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		var interval values.StringValue
		err := yaml.Unmarshal([]byte("10x"), &interval)
		require.NoError(t, err)
		rg.Interval = interval
		_, err = rg.MapToModel()
		require.Error(t, err)
	})
	t.Run("a rule group with an interval containing 'd' should work", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		var interval values.StringValue
		err := yaml.Unmarshal([]byte("2d"), &interval)
		require.NoError(t, err)
		rg.Interval = interval
		rgMapped, err := rg.MapToModel()
		require.NoError(t, err)
		require.Equal(t, int64(48*time.Hour/time.Second), rgMapped.Interval)
	})
	t.Run("a rule group with an empty org id should default to 1", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		rg.OrgID = values.Int64Value{}
		rgMapped, err := rg.MapToModel()
		require.NoError(t, err)
		require.Equal(t, int64(1), rgMapped.OrgID)
	})
	t.Run("a rule group with a negative org id should default to 1", func(t *testing.T) {
		rg := validRuleGroupV1(t)
		orgID := values.Int64Value{}
		err := yaml.Unmarshal([]byte("-1"), &orgID)
		require.NoError(t, err)
		rg.OrgID = orgID
		rgMapped, err := rg.MapToModel()
		require.NoError(t, err)
		require.Equal(t, int64(1), rgMapped.OrgID)
	})
}

func TestRules(t *testing.T) {
	t.Run("a valid rule should not error", func(t *testing.T) {
		rule := validRuleV1(t)
		_, err := rule.mapToModel(1)
		require.NoError(t, err)
	})
	t.Run("a rule with out a uid should error", func(t *testing.T) {
		rule := validRuleV1(t)
		rule.UID = values.StringValue{}
		_, err := rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with out a title should error", func(t *testing.T) {
		rule := validRuleV1(t)
		rule.Title = values.StringValue{}
		_, err := rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with out a for duration should error", func(t *testing.T) {
		rule := validRuleV1(t)
		rule.For = values.StringValue{}
		_, err := rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with an invalid for duration should error", func(t *testing.T) {
		rule := validRuleV1(t)
		forDuration := values.StringValue{}
		err := yaml.Unmarshal([]byte("10x"), &forDuration)
		rule.For = forDuration
		require.NoError(t, err)
		_, err = rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with a for duration containing 'd' should work", func(t *testing.T) {
		rule := validRuleV1(t)
		forDuration := values.StringValue{}
		err := yaml.Unmarshal([]byte("2d"), &forDuration)
		rule.For = forDuration
		require.NoError(t, err)
		ruleMapped, err := rule.mapToModel(1)
		require.NoError(t, err)
		require.Equal(t, 48*time.Hour, ruleMapped.For)
	})
	t.Run("a rule with out a condition should error", func(t *testing.T) {
		rule := validRuleV1(t)
		rule.Condition = values.StringValue{}
		_, err := rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with out data should error", func(t *testing.T) {
		rule := validRuleV1(t)
		rule.Data = []QueryV1{}
		_, err := rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with out execErrState should have sane defaults", func(t *testing.T) {
		rule := validRuleV1(t)
		ruleMapped, err := rule.mapToModel(1)
		require.NoError(t, err)
		require.Equal(t, ruleMapped.ExecErrState, models.AlertingErrState)
	})
	t.Run("a rule with invalid execErrState should error", func(t *testing.T) {
		rule := validRuleV1(t)
		execErrState := values.StringValue{}
		err := yaml.Unmarshal([]byte("abc"), &execErrState)
		require.NoError(t, err)
		rule.ExecErrState = execErrState
		_, err = rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with a valid execErrState should map it correctly", func(t *testing.T) {
		rule := validRuleV1(t)
		execErrState := values.StringValue{}
		err := yaml.Unmarshal([]byte(models.OkErrState), &execErrState)
		require.NoError(t, err)
		rule.ExecErrState = execErrState
		ruleMapped, err := rule.mapToModel(1)
		require.NoError(t, err)
		require.Equal(t, ruleMapped.ExecErrState, models.OkErrState)
	})
	t.Run("a rule with out noDataState should have sane defaults", func(t *testing.T) {
		rule := validRuleV1(t)
		ruleMapped, err := rule.mapToModel(1)
		require.NoError(t, err)
		require.Equal(t, ruleMapped.NoDataState, models.NoData)
	})
	t.Run("a rule with an invalid noDataState should error", func(t *testing.T) {
		rule := validRuleV1(t)
		noDataState := values.StringValue{}
		err := yaml.Unmarshal([]byte("abc"), &noDataState)
		require.NoError(t, err)
		rule.NoDataState = noDataState
		_, err = rule.mapToModel(1)
		require.Error(t, err)
	})
	t.Run("a rule with a valid noDataState should map it correctly", func(t *testing.T) {
		rule := validRuleV1(t)
		noDataState := values.StringValue{}
		err := yaml.Unmarshal([]byte(models.NoData), &noDataState)
		require.NoError(t, err)
		rule.NoDataState = noDataState
		ruleMapped, err := rule.mapToModel(1)
		require.NoError(t, err)
		require.Equal(t, ruleMapped.NoDataState, models.NoData)
	})
}

// This can be removed when the dasboardUid typo support is removed.
func TestRulesDasboardUidTypo(t *testing.T) {
	t.Run("a rule with dasboardUid json should json unmarshal correctly", func(t *testing.T) {
		ruleJson := `{"dasboardUid":"test"}`
		var rule *AlertRuleV1
		err := json.Unmarshal([]byte(ruleJson), &rule)
		require.NoError(t, err)
		require.Equal(t, "test", rule.DashboardUID.Value())
	})
	t.Run("a rule with dashboardUid json should json unmarshal correctly", func(t *testing.T) {
		ruleJson := `{"dashboardUid":"test"}`
		var rule *AlertRuleV1
		err := json.Unmarshal([]byte(ruleJson), &rule)
		require.NoError(t, err)
		require.Equal(t, "test", rule.DashboardUID.Value())
	})
	t.Run("a rule with both dasboardUid and dashboardUid should json unmarshal using dashboardUid", func(t *testing.T) {
		ruleJson := `{"dasboardUid":"test", "dashboardUid":"test2"}`
		var rule *AlertRuleV1
		err := json.Unmarshal([]byte(ruleJson), &rule)
		require.NoError(t, err)
		require.Equal(t, "test2", rule.DashboardUID.Value())
	})

	// Even though the typo only existed in the json tag, we need support in YAML as well since we use yaml.UnmarshalYAML when parsing
	t.Run("a rule with dasboardUid json should yaml unmarshal correctly", func(t *testing.T) {
		ruleJson := `{"dasboardUid":"test"}`
		var rule *AlertRuleV1
		err := yaml.Unmarshal([]byte(ruleJson), &rule)
		require.NoError(t, err)
		require.Equal(t, "test", rule.DashboardUID.Value())
	})
	t.Run("a rule with dashboardUid json should yaml unmarshal correctly", func(t *testing.T) {
		ruleJson := `{"dashboardUid":"test"}`
		var rule *AlertRuleV1
		err := yaml.Unmarshal([]byte(ruleJson), &rule)
		require.NoError(t, err)
		require.Equal(t, "test", rule.DashboardUID.Value())
	})
	t.Run("a rule with both dasboardUid and dashboardUid should yaml unmarshal using dashboardUid", func(t *testing.T) {
		ruleJson := `{"dasboardUid":"test", "dashboardUid":"test2"}`
		var rule *AlertRuleV1
		err := yaml.Unmarshal([]byte(ruleJson), &rule)
		require.NoError(t, err)
		require.Equal(t, "test2", rule.DashboardUID.Value())
	})
}

func validRuleGroupV1(t *testing.T) AlertRuleGroupV1 {
	t.Helper()
	var (
		orgID    values.Int64Value
		name     values.StringValue
		folder   values.StringValue
		interval values.StringValue
	)
	err := yaml.Unmarshal([]byte("1"), &orgID)
	require.NoError(t, err)
	err = yaml.Unmarshal([]byte("Test"), &name)
	require.NoError(t, err)
	err = yaml.Unmarshal([]byte("Test"), &folder)
	require.NoError(t, err)
	err = yaml.Unmarshal([]byte("10s"), &interval)
	require.NoError(t, err)
	return AlertRuleGroupV1{
		OrgID:    orgID,
		Name:     name,
		Folder:   folder,
		Interval: interval,
		Rules:    []AlertRuleV1{},
	}
}

func validRuleV1(t *testing.T) AlertRuleV1 {
	t.Helper()
	var (
		title       values.StringValue
		uid         values.StringValue
		forDuration values.StringValue
		condition   values.StringValue
	)
	err := yaml.Unmarshal([]byte("test"), &title)
	require.NoError(t, err)
	err = yaml.Unmarshal([]byte("test_uid"), &uid)
	require.NoError(t, err)
	err = yaml.Unmarshal([]byte("10s"), &forDuration)
	require.NoError(t, err)
	err = yaml.Unmarshal([]byte("A"), &condition)
	require.NoError(t, err)
	return AlertRuleV1{
		Title:     title,
		UID:       uid,
		For:       forDuration,
		Condition: condition,
		Data:      []QueryV1{{}},
	}
}
