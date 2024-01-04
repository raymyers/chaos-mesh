import { useEffect } from 'react'

import { OidcAuthService } from '../../oidc/OidcAuthService'

const OidcSigninCallback = () => {
  console.log('OIDCSigninCallback Signin Callback -> ACK')

  useEffect(() => {
    const oidcAuthService = new OidcAuthService()

    console.log('OIDCSigninCallback Signin Callback -> Entry')
    console.log('OIDCSigninCallback Signin Callback -> authService created')
    oidcAuthService.signinCallback()
    console.log('OIDCSigninCallback Signin Callback -> authService called')
  }, [])

  return <div>Processing Sign-in Request</div>
}

export default OidcSigninCallback
