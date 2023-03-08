package oauthimpl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models/roletype"
	entac "github.com/grafana/grafana/pkg/services/accesscontrol"
	ossac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/oauthserver"
	"github.com/grafana/grafana/pkg/services/oauthserver/api"
	"github.com/grafana/grafana/pkg/services/oauthserver/oauthstore"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/secrets/kvstore"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

type OAuth2ServiceImpl struct {
	acSvc         entac.Service
	memstore      *storage.MemoryStore
	sqlstore      *oauthstore.Store
	oauthProvider fosite.OAuth2Provider
	logger        log.Logger
	accessControl ossac.AccessControl
	acService     entac.Service
	saService     serviceaccounts.Service
	userService   user.Service
	teamService   team.Service
}

func NewProvider(config *fosite.Config, storage interface{}, key interface{}) fosite.OAuth2Provider {
	keyGetter := func(context.Context) (interface{}, error) {
		return key, nil
	}
	return compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, compose.NewOAuth2HMACStrategy(config), config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.RFC7523AssertionGrantFactory,

		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)
}

func ProvideService(router routing.RouteRegister, db db.DB, cfg *setting.Cfg, skv kvstore.SecretsKVStore,
	svcAccSvc serviceaccounts.Service, accessControl ossac.AccessControl, acSvc entac.Service, userSvc user.Service,
	teamSvc team.Service) (*OAuth2ServiceImpl, error) {

	// TODO: Make this configurable
	config := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		// GlobalSecret:        []byte("some-cool-secret-that-is-32bytes"),
		TokenURL:          fmt.Sprintf("%voauth2/token", cfg.AppURL),
		AccessTokenIssuer: cfg.AppURL,
		IDTokenIssuer:     cfg.AppURL,
		ScopeStrategy:     fosite.WildcardScopeStrategy,
		// ...
	}

	privateKey, errLoadKey := loadServerPrivateKey(skv)
	if errLoadKey != nil {
		// TODO log something
		return nil, errLoadKey
	}

	// storage := memstorage.NewGrafanaPluginAuthStore(config)

	s := &OAuth2ServiceImpl{
		accessControl: accessControl,
		acSvc:         acSvc,
		memstore:      storage.NewMemoryStore(),
		sqlstore:      oauthstore.NewStore(db),
		logger:        log.New("oauthserver"),
		userService:   userSvc,
		saService:     svcAccSvc,
		teamService:   teamSvc,
		acService:     acSvc,
	}

	api := api.NewAPI(router, s)
	api.RegisterAPIEndpoints()

	s.oauthProvider = NewProvider(config, s, privateKey)

	return s, nil
}

func loadServerPrivateKey(skv kvstore.SecretsKVStore) (*rsa.PrivateKey, error) {
	privatePem, ok, err := skv.Get(context.Background(), oauthserver.TmpOrgID, "OAuthServerPrivatePEM", "oauthserverpem")
	if err != nil {
		return nil, err
	}
	var privateKey *rsa.PrivateKey
	if !ok {
		var errGenKey error
		privateKey, errGenKey = rsa.GenerateKey(rand.Reader, 2048)
		if errGenKey != nil {
			return nil, errGenKey
		}
		privateKeyPem := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}))
		if err = skv.Set(context.Background(), oauthserver.TmpOrgID, "OAuthServerPrivatePEM", "oauthserverpem", privateKeyPem); err != nil {
			return nil, err
		}
	} else {
		var errParseKey error
		privateKeyPem, _ := pem.Decode([]byte(privatePem))
		privateKey, errParseKey = x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
		if errParseKey != nil {
			return nil, errParseKey
		}
	}
	return privateKey, nil
}

func (s *OAuth2ServiceImpl) RandString(n int) (string, error) {
	res := make([]byte, n)
	_, err := rand.Read(res)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(res), nil
}

// TODO it would be great to create the service account in the same session
func (s *OAuth2ServiceImpl) RegisterApp(ctx context.Context, registration *oauthserver.AppRegistration) (*oauthserver.ClientDTO, error) {
	client := oauthserver.Client{
		AppName:                registration.AppName,
		ImpersonatePermissions: registration.ImpersonatePermissions,
	}
	if registration.RedirectURI != nil {
		client.RedirectURI = *registration.RedirectURI
	}

	// res.Domain = "http://localhost" // TODO: Make this configurable

	id, err := s.RandString(20)
	if err != nil {
		s.logger.Error("Error gen id", "client", client, "error", err)
		return nil, err
	}
	client.ClientID = id
	secret, err := s.RandString(40)
	if err != nil {
		s.logger.Error("Error gen secret", "client", client, "error", err)
		return nil, err
	}
	client.Secret = secret

	// Assign permissions to a service account that will be associated to the App
	if len(registration.Permissions) > 0 {
		s.logger.Debug("Generate service account")
		id, err := s.createServiceAccount(ctx, registration)
		if err != nil {
			return nil, err
		}
		client.ServiceAccountID = id
	}

	client.GrantTypes = strings.Join(s.computeGrantTypes(registration), ",")

	// Handle RSA key options
	s.logger.Debug("Handle key options")
	keys, err := s.handleKeyOptions(ctx, registration)
	if err != nil {
		s.logger.Error("Error handling key options", "client", client, "error", err)
		return nil, err
	}
	client.PublicPem = []byte(keys.PublicPem)

	s.logger.Info("Registering app", "client", client)
	err = s.sqlstore.RegisterApp(ctx, &client)
	if err != nil {
		return nil, err
	}
	dto := client.ToDTO()
	dto.KeyResult = keys
	return dto, nil
}

func (s *OAuth2ServiceImpl) computeGrantTypes(registration *oauthserver.AppRegistration) []string {
	grantTypes := []string{}

	// If the app has permissions, it can use the client credentials grant type
	if len(registration.Permissions) > 0 {
		grantTypes = append(grantTypes, string(fosite.GrantTypeClientCredentials))
	}

	// If the app has impersonate permissions, it can use the JWT bearer grant type
	if len(registration.ImpersonatePermissions) > 0 {
		grantTypes = append(grantTypes, string(fosite.GrantTypeJWTBearer))
	}

	return grantTypes
}

func (s *OAuth2ServiceImpl) createServiceAccount(ctx context.Context, registration *oauthserver.AppRegistration) (int64, error) {
	newRole := func(r roletype.RoleType) *roletype.RoleType {
		return &r
	}
	newBool := func(b bool) *bool {
		return &b
	}

	// TODO: Can we use ServiceAccounts in global orgs in the future? As apps are available accross all orgs.
	// FIXME currently using orgID 1
	sa, err := s.saService.CreateServiceAccount(ctx, oauthserver.TmpOrgID, &serviceaccounts.CreateServiceAccountForm{
		Name:       registration.AppName,
		Role:       newRole(roletype.RoleViewer), // TODO: Use empty role
		IsDisabled: newBool(false),
	})
	if err != nil {
		return -1, err
	}

	// role, err := s.acSvc.CreateRole(ctx, entac.GlobalOrgID, entac.CreateRoleCommand{
	// 	UID:         fmt.Sprintf("app_servicesaccounts_%v_permissions", sa.Id), // FIXME use managed instead of app
	// 	Name:        fmt.Sprintf("app:servicesaccounts:%v:permissions", sa.Id), // FIXME use managed instead of app
	// 	Permissions: registration.Permissions,
	// 	Description: fmt.Sprintf("Managed role for service account %v created for %s", sa.Id, registration.AppName),
	// 	Version:     1,
	// 	Hidden:      true,
	// })
	// if err != nil {
	// 	return -1, err
	// }

	// if err = s.acSvc.AddUserRole(ctx, entac.GlobalOrgID, entac.AddUserRoleCommand{
	// 	Global:  true,
	// 	RoleUID: role.UID,
	// 	UserID:  sa.Id,
	// }); err != nil {
	// 	return -1, err
	// }

	return sa.Id, nil
}

func (s *OAuth2ServiceImpl) handleKeyOptions(ctx context.Context, registration *oauthserver.AppRegistration) (*oauthserver.KeyResult, error) {
	if registration.Key == nil {
		return nil, nil
	}

	if registration.Key.Generate {
		RSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return &oauthserver.KeyResult{
			PrivatePem: string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(RSAKey),
			})),
			PublicPem: string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&RSAKey.PublicKey),
			})),
			Generated: true,
		}, nil
	}

	// TODO allow specifying a URL to get the public key
	// if registration.Key.URL != "" {
	// 	return &oauthserver.KeyResult{
	// 		URL: registration.Key.URL,
	// 	}, nil
	// }

	if registration.Key.PublicPEM != "" {
		return &oauthserver.KeyResult{
			PublicPem: registration.Key.PublicPEM,
		}, nil
	}

	return nil, fmt.Errorf("at least one key option must be specified")
}

func (s *OAuth2ServiceImpl) GetApp(ctx context.Context, id string) (*oauthserver.Client, error) {
	app, err := s.sqlstore.GetApp(ctx, id)
	if err != nil {
		return nil, err
	}

	// Retrieve self permissions and generate a signed in user
	sa, err := s.saService.RetrieveServiceAccount(ctx, oauthserver.TmpOrgID, app.ServiceAccountID)
	if err != nil {
		return nil, err
	}

	app.SignedInUser = &user.SignedInUser{
		UserID:      sa.Id,
		OrgID:       oauthserver.TmpOrgID,
		OrgRole:     org.RoleType(sa.Role), // Need this to compute the permissions in OSS
		Login:       sa.Login,
		Name:        sa.Name,
		Permissions: map[int64]map[string][]string{},
	}
	app.SelfPermissions, err = s.acSvc.GetUserPermissions(ctx, app.SignedInUser, ossac.Options{})
	if err != nil {
		return nil, err
	}
	app.SignedInUser.Permissions[oauthserver.TmpOrgID] = ossac.GroupScopesByAction(app.SelfPermissions)

	// TODO: Retrieve org memberships
	app.OrgIDs = []int64{oauthserver.TmpOrgID}

	return app, nil
}

// TODO cache scopes
// ComputeClientScopesOnTarget computes the scopes that a client has on a specific user (targetLogin) only searching in the subset of scopes provided
func (s *OAuth2ServiceImpl) computeClientScopesOnUser(ctx context.Context, client *oauthserver.Client, userID int64) ([]string, error) {
	// TODO I used userID here as we used it for the ext jwt service, but it would be better to use login as app shouldn't know the user id
	// TODO Inefficient again as we fetch the user to populate the id_token again later
	targetUser, err := s.userService.GetByID(ctx, &user.GetUserByIDQuery{ID: userID})
	if err != nil {
		return nil, err
	}

	res := []string{}
	for _, scope := range client.GetScopes() {
		hasAccess := false
		var errAccess error
		if strings.HasPrefix(scope, "org.") {
			hasAccess = true
		}
		switch string(scope) {
		case "openid":
			hasAccess = true
		case "email", "profile":
			hasAccess, errAccess = s.accessControl.Evaluate(ctx, client.SignedInUser, ossac.EvalPermission(
				"users:read", fmt.Sprintf("global.users:id:%v", targetUser.ID)))
		case "permissions":
			hasAccess, errAccess = s.accessControl.Evaluate(ctx, client.SignedInUser, ossac.EvalPermission(
				"users.permissions:read", fmt.Sprintf("users:id:%v", targetUser.ID)))
		case "teams":
			// We don't need to check whether the service account has access to the specific teams of the target user
			// because the filtering will be done by the Team service based on the service account permissions
			hasAccess, errAccess = s.accessControl.Evaluate(ctx, client.SignedInUser, ossac.EvalPermission("teams:read"))
		}
		if errAccess != nil {
			return nil, errAccess
		}
		if hasAccess {
			res = append(res, string(scope))
		}
	}
	return res, nil
}