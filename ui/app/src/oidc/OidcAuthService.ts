/*
 * Copyright 2021 Chaos Mesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
import { UserManager, WebStorageStateStore } from 'oidc-client-ts'

import { ConfigChaosDashboardConfig } from '../openapi/index.schemas'

export class OidcAuthService {
  userManager
  userManagerConfig

  constructor() {
    this.userManagerConfig = {
      authority: 'authority_uri_here',
      client_id: 'client_id_here', // Okta provided client id
      redirect_uri: 'http://localhost:3000/login/callback',
      //silent_redirect_uri
      //post_logout_redirect_uri
      //response_type
      //scope
      userStore: new WebStorageStateStore({ store: window.localStorage }),
    }
    this.userManager = new UserManager(this.userManagerConfig)
  }

  signin = async () => {
    try {
      await this.userManager.signinRedirect()
    } catch {
      console.error('OIDC signin error')
    }
  }

  signinCallback = async () => {
    try {
      await this.userManager.signinRedirectCallback()
      // TODO: redirect?
      window.location.replace(this.userManagerConfig.redirect_uri)
    } catch {
      console.error('OIDC signin callback error')
    }
  }

  // TODO: signout
}
