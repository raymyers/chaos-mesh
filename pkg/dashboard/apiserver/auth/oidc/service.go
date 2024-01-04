// Copyright 2023 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package oidc

import (
	"net/http"
	"net/url"
	"path"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	//"github.com/hashicorp/cap/oidc"
	"golang.org/x/oauth2"

	config "github.com/chaos-mesh/chaos-mesh/pkg/config"
	"github.com/chaos-mesh/chaos-mesh/pkg/dashboard/apiserver/utils"
)

type Service struct {
	clientId  string
	authority string
	rootUrl   *url.URL
	logger    logr.Logger
}

// OidcConfig is separate from the Oauth configurations currently available
// in that it does not rely on a secret, but instead has an authority that
// must be passed and utilized
type OidcConfig struct {
	// ClientID is the application's ID as registered with the provider.
	ClientID string

	// Authority is the URL of the OIDC/OAuth2 provider.
	Authority string

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// TODO: Add Optional fields
	// ResponseType optionally specifies the type of response desired from the provider.
	ResponseType string

	// Scope specifies optional requested permissions.
	Scopes []string
}

// NewService returns an experiment service instance.
func NewService(
	conf *config.ChaosDashboardConfig,
	logger logr.Logger,
) (*Service, error) {
	rootUrl, err := url.Parse(conf.RootUrl)
	if err != nil {
		return nil, err
	}
	if rootUrl.Path == "" {
		rootUrl.Path = "/"
	}

	return &Service{
		clientId:  conf.OidcClientId,
		authority: conf.OidcAuthority,
		rootUrl:   rootUrl,
		logger:    logger.WithName("oidc auth api"),
	}, nil
}

// Register mounts HTTP handler on the mux.
func Register(r *gin.RouterGroup, s *Service, conf *config.ChaosDashboardConfig) {
	// If the oidc security mode is not set, just skip the registration
	// TODO: put this back in once the security mode is set up
	//if !conf.OidcSecurityMode {
	//	return
	//}

	r.Use(s.Middleware)

	endpoint := r.Group("/auth/oidc")
	endpoint.GET("/redirect", s.handleRedirect)
	endpoint.GET("/callback", s.authCallback)
}

func (s *Service) getOidcConfig(c *gin.Context) oauth2.Config {
	url := *s.rootUrl
	url.Path = path.Join(s.rootUrl.Path, "./api/auth/oidc/callback")

	oktaEndpoint := oauth2.Endpoint{
		AuthURL:  "https://id.indeed.tech/oauth2/ausdemmtrnyZ8dG1J4x7/v1/authorize",
		TokenURL: "https://id.indeed.tech/oauth2/ausdemmtrnyZ8dG1J4x7/v1/token",
	}

	return oauth2.Config{
		ClientID: s.clientId,
		// ClientSecret shouldn't be required for Authorization Flow with PKCE using oidc...
		RedirectURL: url.String(),
		Scopes: []string{
			"openid",
		},
		Endpoint: oktaEndpoint,
	}
}

func (s *Service) handleRedirect(c *gin.Context) {
	oauth := s.getOidcConfig(c)
	uri := oauth.AuthCodeURL("", oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	c.Redirect(http.StatusFound, uri)
}

func (s *Service) authCallback(c *gin.Context) {
	ctx := c.Request.Context()

	oidc := s.getOidcConfig(c)
	oauth2Token, err := oidc.Exchange(ctx, c.Request.URL.Query().Get("code"), oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	if err != nil {
		utils.SetAPIError(c, utils.ErrInternalServer.WrapWithNoMessage(err))
		return
	}

	setCookie(c, oauth2Token)
	target := url.URL{
		Path: "/",
	}
	c.Redirect(http.StatusFound, target.RequestURI())
}
