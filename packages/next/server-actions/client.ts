import { CookieStorage } from '@logto/node';
import NodeClient from '@logto/node/edge';
import LogtoNextBaseClient from '../src/client.js';

class LogtoClient extends LogtoNextBaseClient {
    constructor(config) {
        super(config, {
            NodeClient,
        });
    }
    async handleSignIn(options, interactionMode) {
        const nodeClient = await this.createNodeClient();
        const finalOptions = typeof options === 'string' || options instanceof URL
            ? { redirectUri: options, interactionMode }
            : options;
        await nodeClient.signIn(finalOptions);
        if (!this.navigateUrl) {
            // Not expected to happen
            throw new Error('navigateUrl is not set');
        }
        return {
            url: this.navigateUrl,
        };
    }
    /**
     * Init sign-out and return the url to redirect to Logto.
     *
     * @param redirectUri the uri (postSignOutUri) to redirect to after sign out
     * @returns the url to redirect to
     */
    async handleSignOut(redirectUri = this.config.baseUrl) {
        const nodeClient = await this.createNodeClient();
        await nodeClient.signOut(redirectUri);
        await this.storage?.destroy();
        if (!this.navigateUrl) {
            // Not expected to happen
            throw new Error('navigateUrl is not set');
        }
        return this.navigateUrl;
    }
    /**
     * Handle sign-in callback from Logto.
     *
     * @param callbackUrl the uri (callbackUri) to redirect to after sign in, should match the one used in handleSignIn
     */
    async handleSignInCallback(callbackUrl) {
        const nodeClient = await this.createNodeClient();
        await nodeClient.handleSignInCallback(callbackUrl);
    }
    /**
     * Get Logto context from cookies.
     *
     * @param config additional configs of GetContextParameters
     * @returns LogtoContext
     */
    async getLogtoContext(config = {}) {
        const nodeClient = await this.createNodeClient({ ignoreCookieChange: true });
        const context = await nodeClient.getContext(config);
        return context;
    }
    
    async createNodeClient({ ignoreCookieChange } = {}) {
        const { cookies } = await import('next/headers');
        const cookiesData = await cookies();
        this.storage = new CookieStorage({
            encryptionKey: this.config.cookieSecret,
            cookieKey: `logto:${this.config.appId}`,
            isSecure: this.config.cookieSecure,
            getCookie: (...args) => {
                return cookiesData.get(...args)?.value ?? '';
            },
            setCookie: (...args) => {
                // In server component (RSC), it is not allowed to modify cookies, see https://nextjs.org/docs/app/api-reference/functions/cookies#cookiessetname-value-options.
                if (!ignoreCookieChange) {
                    cookiesData.set(...args);
                }
            },
        });
        await this.storage.init();
        return new this.adapters.NodeClient(this.config, {
            storage: this.storage,
            navigate: (url) => {
                this.navigateUrl = url;
            },
        });
    }

}

export { LogtoClient as default };
