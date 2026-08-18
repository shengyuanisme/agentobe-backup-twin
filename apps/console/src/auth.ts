import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";

const authority = import.meta.env.VITE_OIDC_AUTHORITY as string | undefined;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined;

export const oidcConfigured = Boolean(authority && clientId);

const manager = oidcConfigured
  ? new UserManager({
      authority: authority!,
      client_id: clientId!,
      redirect_uri: import.meta.env.VITE_OIDC_REDIRECT_URI as string | undefined
        ?? `${window.location.origin}/`,
      post_logout_redirect_uri: import.meta.env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI as string | undefined
        ?? `${window.location.origin}/`,
      response_type: "code",
      scope: import.meta.env.VITE_OIDC_SCOPE as string | undefined
        ?? "openid profile email",
      automaticSilentRenew: true,
      monitorSession: false,
      userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    })
  : undefined;

export async function initializeAuth(): Promise<User | null> {
  if (!manager) return null;
  const params = new URLSearchParams(window.location.search);
  if (params.has("code") && params.has("state")) {
    const user = await manager.signinRedirectCallback();
    window.history.replaceState({}, document.title, window.location.pathname);
    return user;
  }
  const user = await manager.getUser();
  return user && !user.expired ? user : null;
}

export async function login(): Promise<void> {
  if (!manager) throw new Error("OIDC is not configured for this Console build.");
  await manager.signinRedirect();
}

export async function logout(): Promise<void> {
  if (!manager) return;
  await manager.signoutRedirect();
}
