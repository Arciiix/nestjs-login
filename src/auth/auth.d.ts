interface IJwtPayload {
  id: string;
  login: string;
  authenticated: boolean;
}

interface IUserReturnType {
  user: IUserSafe;
  refreshToken: string;
  accessToken: string;
  isAuthenticated: boolean;
}

interface IUserSafe {
  id: string;
  login: string;
  email: string;
  isTwoFaEnabled: boolean;
}

interface ISuccessReturnType {
  success: boolean;
}

interface ITwoFactorAuthInfo {
  isEnabled: boolean;
  secret?: string;
  uri?: string;
  recoveryCode?: string;
  qrCodeEncodedString?: string;
}

export type {
  IJwtPayload,
  IUserReturnType,
  IUserSafe,
  ISuccessReturnType,
  ITwoFactorAuthInfo,
};
