import { OidcAuthService } from '../../oidc/OidcAuthService'

const OidcSigninCallback = () => {
  const authService = new OidcAuthService()
  authService.signinCallback()
  return null
}

export default OidcSigninCallback
