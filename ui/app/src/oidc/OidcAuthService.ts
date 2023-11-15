import { UserManager, WebStorageStateStore } from 'oidc-client-ts'

export class OidcAuthService {
  userManager
  userManagerConfig = {
    authority: 'authority_uri_here',
    client_id: 'client_id_here', // Okta provided client id
    redirect_uri: 'http://localhost:3000/login/callback',
    //silent_redirect_uri
    //post_logout_redirect_uri
    //response_type
    //scope
    userStore: new WebStorageStateStore({ store: window.localStorage }),
  }

  constructor() {
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
