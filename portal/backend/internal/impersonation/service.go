/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package impersonation

import (
	"github.com/wso2/openfgc/portal/backend/internal/proxy"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Service is the thin integration layer Nominee Service delegates to: mint an
// IS impersonation token, and forward a consent action to the Consent Server.
// It has no opinion on whether a nominee/owner pairing is valid - Nominee
// Service has already decided that before either method here is called.
type Service struct {
	is    *ISClient
	proxy *proxy.Service
}

// NewService builds an impersonation service from app config.
func NewService(cfg config.Config) (*Service, error) {
	proxyService, err := proxy.NewService(cfg.Proxy)
	if err != nil {
		return nil, err
	}
	return &Service{
		is:    NewISClient(cfg.IdentityServer),
		proxy: proxyService,
	}, nil
}

// IS exposes the Identity Server client for the acting handlers.
func (s *Service) IS() *ISClient {
	return s.is
}

// Proxy exposes the underlying consent-server proxy for the handler layer.
func (s *Service) Proxy() *proxy.Service {
	return s.proxy
}
