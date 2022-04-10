interface IJwtPayload {
  id: string;
  login: string;
}

interface IUserReturnType {
  user: User;
  refreshToken: string;
  accessToken: string;
}

interface ISuccessReturnType {
  success: boolean;
}

interface ITwoFactorAuthInfo {
  isEnabled: boolean;
  uri?: string;
  recoveryCode?: string;
  qrCodeEncodedString?: string;
}

export type {
  IJwtPayload,
  IUserReturnType,
  ISuccessReturnType,
  ITwoFactorAuthInfo,
};
