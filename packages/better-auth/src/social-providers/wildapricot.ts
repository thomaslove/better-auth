import { betterFetch } from "@better-fetch/fetch";
import { APIError } from "better-call";
import {
  createAuthorizationURL,
  validateAuthorizationCode,
  type OAuth2Tokens,
  type OAuthProvider,
} from "../oauth2";

export interface WildApricotOptions {
  clientId: string;
  clientSecret: string;
  siteName?: string;
  accountId: string;
  redirectURI?: string;
  scopes?: string[];
  mapProfileToUser?: (profile: WildApricotProfile) => {
    membershipStatus?: string;
    membershipLevel?: string;
    isActiveMember?: boolean;
    isAdmin?: boolean;
    [key: string]: any;
  };
}

interface WildApricotProfile {
  Id: number;
  FirstName: string;
  LastName: string;
  Email: string;
  Status: string;
  MembershipLevel?: {
    Id: number;
    Name: string;
  };
  IsAccountAdministrator: boolean;
  AdministrativeRoleTypes: string[];
}

export const wildApricot = (options: WildApricotOptions): OAuthProvider => {
  const { clientId, clientSecret, siteName, accountId, redirectURI, scopes } = options;
  
  const WA_SITE_URL = siteName ? `https://${siteName}.wildapricot.org` : `https://www.wildapricot.org`;
  const WA_BASE_URL = "https://oauth.wildapricot.org";
  const WA_API_URL = "https://api.wildapricot.org";

  return {
    id: "wildapricot",
    name: "Wild Apricot",
    
    createAuthorizationURL(data) {
      return createAuthorizationURL({
        id: "wildapricot",
        options: {
          clientId,
          clientSecret,
          redirectURI,
        },
        authorizationEndpoint: `${WA_SITE_URL}/sys/login/OAuthLogin`,
        state: data.state,
        scopes: scopes || ["contacts_me"],
        redirectURI: data.redirectURI,
      });
    },

    async validateAuthorizationCode(data) {
      return validateAuthorizationCode({
        code: data.code,
        codeVerifier: data.codeVerifier,
        redirectURI: data.redirectURI,
        options: {
          clientId,
          clientSecret,
          redirectURI,
        },
        tokenEndpoint: `${WA_BASE_URL}/auth/token`,
        authentication: "basic",
      });
    },

    async refreshAccessToken(refreshToken: string): Promise<OAuth2Tokens> {
      const response = await betterFetch<{
        access_token: string;
        refresh_token: string;
        expires_in: number;
        scope: string;
      }>(`${WA_BASE_URL}/auth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
      });

      if (response.error) {
        throw new APIError("BAD_REQUEST", {
          message: "Failed to refresh access token",
        });
      }

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        accessTokenExpiresAt: response.data.expires_in
          ? new Date(Date.now() + response.data.expires_in * 1000)
          : undefined,
        scopes: response.data.scope?.split(" "),
      };
    },

    async getUserInfo(tokens) {
      const userInfo = await betterFetch<WildApricotProfile>(`${WA_API_URL}/v2.1/accounts/${accountId}/contacts/me`, {
        headers: {
          Authorization: `Bearer ${tokens.accessToken}`,
          Accept: "application/json",
        },
      });

      if (userInfo.error || !userInfo.data) {
        return null;
      }

      const profile = userInfo.data;
      
      const isActiveMember = (status: string) => {
        return ["Active", "PendingRenewal", "PendingLevelChange"].includes(status);
      };

      const baseUser = {
        id: String(profile.Id),
        name: `${profile.FirstName} ${profile.LastName}`,
        email: profile.Email,
        emailVerified: true,
        image: null,
      };

      // Apply custom mapping if provided
      const additionalFields = options.mapProfileToUser?.(profile) || {};

      return {
        user: {
          ...baseUser,
          // Default Wild Apricot fields
          membershipStatus: profile.Status ?? "NoMembership",
          membershipLevel: profile.MembershipLevel?.Name ?? null,
          isActiveMember: isActiveMember(profile.Status),
          isAdmin: profile.IsAccountAdministrator,
          // Override with custom mapping
          ...additionalFields,
        },
        data: profile,
      };
    },
  };
};