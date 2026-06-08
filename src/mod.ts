/**
 * Public entrypoint for @murich/supabase-multi-issuer-jwt.
 */

export { signMultiIssuerJwt } from "./sign.ts";
export { verifyMultiIssuerJwt } from "./verify.ts";
export { createJwtSwapProxy } from "./proxy.ts";
export {
  deactivateIssuer,
  getPublicKey,
  listPublicKeys,
  registerPublicKey,
} from "./registry.ts";
export type {
  Algorithm,
  MultiIssuerJwtClaims,
  ProxyOptions,
  PublicKeyRow,
  RegisterOptions,
  SignOptions,
  VerifyOptions,
  VerifyResult,
} from "./types.ts";
export { JwtVerificationError } from "./types.ts";
