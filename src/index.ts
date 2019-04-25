import auth0 from 'auth0-js'
import Cookie from 'js-cookie'
import jwtDecode from 'jwt-decode'
import nextCookies from 'next-cookies'

export interface AuthHelperOpts {
  clientId: string,
  domain: string,
  baseUrl?: string
}

export type NextContext = any

export interface Auth0User {
  email: string,
  picture: string
}

class AuthHelper {
  constructor (
    private readonly opts: AuthHelperOpts
  ) {}

  private getAuth0 (options?: auth0.AuthOptions) {
    return new auth0.WebAuth(options)
  }

  private getOptions () {
    return {
      clientID: this.opts.clientId,
      domain: this.opts.domain,
      responseType: 'token id_token',
      redirectUri: `${this.getBaseUrl()}/auth/signed-in`,
      scope: 'openid profile email'
    }
  }

  private getBaseUrl () {
    return this.opts.baseUrl || `${window.location.protocol}//${window.location.host}`
  }

  login () {
    return this.getAuth0(this.getOptions()).authorize()
  }

  async parseHash () {
    try {
      return await new Promise<auth0.Auth0DecodedHash>((resolve, reject) => {
        this.getAuth0().parseHash((err, result) => {
          if (err) {
            reject(err)
          } else {
            resolve(result)
          }
        })
      })
    } catch (err) {
      throw new Error(err.message)
    }
  }

  logout () {
    return this.getAuth0().logout({ returnTo: this.getBaseUrl() })
  }

  setToken (idToken: string, accessToken: string) {
    if (!(process as any).browser) return

    Cookie.set('idToken', idToken)
    Cookie.set('accessToken', accessToken)
  }

  unsetToken () {
    if (!(process as any).browser) return

    Cookie.remove('idToken')
    Cookie.remove('accessToken')
  }

  getIdToken (ctx: NextContext): string {
    const { idToken } = nextCookies(ctx)
    if (!idToken) throw new Error(`ID token not found`)
    return idToken
  }

  getAccessToken (ctx: NextContext): string {
    const { accessToken } = nextCookies(ctx)
    if (!accessToken) throw new Error(`Access token not found`)
    return accessToken
  }

  getUser (ctx: NextContext): Auth0User {
    return jwtDecode(this.getIdToken(ctx))
  }
}

export default function createAuthHelper (opts: AuthHelperOpts) {
  return new AuthHelper(opts)
}
