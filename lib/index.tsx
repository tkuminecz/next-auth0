import * as Cookie from 'js-cookie'
import * as jwtDecode from 'jwt-decode'
import * as nextCookies from 'next-cookies'
import * as React from 'react'
import auth0 from 'auth0-js'
import Router from 'next/router'

export interface AuthHelperOpts {
  clientId: string,
  domain: string,
  baseUrl?: string,
  loginCallbackPath?: string
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

  private getAuth0 (options: Partial<auth0.AuthOptions> = {}) {
    return new auth0.WebAuth({
      clientID: this.opts.clientId,
      domain: this.opts.domain,
      ...options
    })
  }

  private getBaseUrl () {
    return this.opts.baseUrl || `${window.location.protocol}//${window.location.host}`
  }

  login = () => {
    const auth0 = this.getAuth0({
      redirectUri: `${this.getBaseUrl()}${this.opts.loginCallbackPath || '/auth/signed-in'}`,
      responseType: 'token id_token',
      scope: 'openid profile email'
    })
    return auth0.authorize()
  }

  parseHash = async () => {
    return new Promise<auth0.Auth0DecodedHash>((resolve, reject) => {
      this.getAuth0().parseHash((err, result) => {
        if (err) {
          reject(err)
        } else {
          resolve(result)
        }
      })
    })
  }

  loginCallback = async () => {
    const result = await this.parseHash()
    return setToken(result.idToken, result.accessToken)
  }

  logout = () => {
    unsetToken()
    const returnTo = this.getBaseUrl()
    console.log('returnTo', returnTo)
    return this.getAuth0().logout({ returnTo })
  }

  SignInPage = () =>
    <SignInPage login={this.login}/>

  SignedInPage = (props: { bounceTo: string }) =>
    <SignedInPage loginCallback={this.loginCallback} {...props}/>

  SignOffPage = () =>
    <SignOffPage logout={this.logout}/>
}

export default function createAuthHelper (opts: AuthHelperOpts) {
  return new AuthHelper(opts)
}

export function setToken (idToken: string, accessToken: string) {
  if (!(process as any).browser) return

  Cookie.set('idToken', idToken)
  Cookie.set('accessToken', accessToken)
}

export function unsetToken () {
  if (!(process as any).browser) return

  Cookie.remove('idToken')
  Cookie.remove('accessToken')
}

class MissingIdTokenError extends Error {}

export function getIdToken (ctx: NextContext): string {
  const { idToken } = nextCookies(ctx)
  if (!idToken) throw new MissingIdTokenError(`ID token not found`)
  return idToken
}

class MissingAccessTokenError extends Error {}

export function getAccessToken (ctx: NextContext): string {
  const { accessToken } = nextCookies(ctx)
  if (!accessToken) throw new MissingAccessTokenError(`Access token not found`)
  return accessToken
}

export function getUser (ctx: NextContext): Auth0User {
  try {
    return jwtDecode(getIdToken(ctx))
  } catch (err) {
    if (err instanceof MissingIdTokenError) {
      return
    } else {
      throw err
    }
  }
}

class SignInPage extends React.Component<{login: Function }> {
  componentDidMount () {
    this.props.login()
  }

  render = () => null
}

class SignedInPage extends React.Component<{ bounceTo: string, loginCallback: Function }> {
  async componentDidMount () {
    await this.props.loginCallback()
    Router.push(this.props.bounceTo)
      .catch(err => console.error(err))
  }

  render = () => null
}

class SignOffPage extends React.Component<{ logout: Function }> {
  componentDidMount () {
    this.props.logout()
  }
  render = () => null
}

export function defaultPage (Page) {
  return class extends React.Component {
    static displayName = `DefaultPage(${Page.displayName || Page.name})`

    static async getInitialProps (ctx) {
      const pageProps = Page.getInitialProps ? await Promise.resolve(Page.getInitialProps(ctx)) : {}
      const authUser = getUser(ctx)
      return {
        ...pageProps,
        authUser,
        isAuthenticated: !!authUser
      }
    }

    render () {
      return (
        <>
          <Page {...this.props}/>
        </>
      )
    }
  }
}

export function SecurePage (NotAuthorized) {
  function securePageHoc (Page) {
    return class extends React.Component<{ isAuthenticated: boolean }> {
      static displayName = `SecurePage(${Page.displayName || Page.name})`

      render () {
        const { isAuthenticated = false } = this.props
        return (isAuthenticated)
          ? (
            <>
              <Page {...this.props}/>
            </>
          )
          : <NotAuthorized {...this.props}/>
      }
    }
  }
  return (Page) => defaultPage(securePageHoc(Page))
}
