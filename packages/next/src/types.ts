import { LogtoConfig } from '@logto/node';
import { IronSession } from 'iron-session';
import { NextApiRequest } from 'next';

export type NextRequestWithIronSession = NextApiRequest & { session: IronSession };

declare module 'iron-session' {
  // Honor module definition
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface IronSessionData {
    accessToken?: string;
    idToken?: string;
    signInSession?: string;
    refreshToken?: string;
  }
}

export type LogtoNextConfig = LogtoConfig & {
  cookieSecret: string;
  cookieSecure: boolean;
  baseUrl: string;
};
