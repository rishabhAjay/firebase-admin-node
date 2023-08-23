/*!
 * @license
 * Copyright 2020 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import fs = require('fs');
//import os = require('os');
//import path = require('path');

import { Credentials as GoogleAuthCredentials, GoogleAuth, CredentialBody, Compute } from 'google-auth-library'
import { Agent } from 'http';
import { Credential, GoogleOAuthAccessToken } from './credential';
import { AppErrorCodes, FirebaseAppError } from '../utils/error';
import { HttpClient, HttpRequestConfig, HttpError, HttpResponse } from '../utils/api-request';
import * as util from '../utils/validator';
import { JSONClient } from 'google-auth-library/build/src/auth/googleauth';

// NOTE: the Google Metadata Service uses HTTP over a vlan
// const GOOGLE_METADATA_SERVICE_HOST = 'metadata.google.internal';
// const GOOGLE_METADATA_SERVICE_TOKEN_PATH = '/computeMetadata/v1/instance/service-accounts/default/token';
// const GOOGLE_METADATA_SERVICE_IDENTITY_PATH = '/computeMetadata/v1/instance/service-accounts/default/identity';
// const GOOGLE_METADATA_SERVICE_PROJECT_ID_PATH = '/computeMetadata/v1/project/project-id';
// const GOOGLE_METADATA_SERVICE_ACCOUNT_ID_PATH = '/computeMetadata/v1/instance/service-accounts/default/email';

const REFRESH_TOKEN_HOST = 'www.googleapis.com';
const REFRESH_TOKEN_PATH = '/oauth2/v4/token';

const SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/firebase.database',
  'https://www.googleapis.com/auth/firebase.messaging',
  'https://www.googleapis.com/auth/identitytoolkit',
  'https://www.googleapis.com/auth/userinfo.email',
];

/**
 * Implementation of ADC that uses google-auth-library-nodejs.
 */
export class ApplicationDefaultCredential implements Credential {

  private readonly googleAuth: GoogleAuth;
  private authClient: JSONClient | Compute;
  private projectId?: string;
  private accountId?: string;
  //private readonly httpAgent?: Agent;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(httpAgent?: Agent) {
    //this.httpAgent = httpAgent;
    this.googleAuth = new GoogleAuth({
      scopes: SCOPES
    });
  }

  public async getAccessToken(): Promise<GoogleOAuthAccessToken> {
    if (!this.authClient) {
      this.authClient = await this.googleAuth.getClient();
    }
    await this.authClient.getAccessToken();
    const credentials = this.authClient.credentials;
    return populateCredential(credentials);
  }

  public getProjectId(): Promise<string> {
    if (this.projectId) {
      return Promise.resolve(this.projectId);
    }
    return this.googleAuth.getProjectId();
  }

  public async isComputeEngineCredential(): Promise<boolean> {
    if (!this.authClient) {
      this.authClient = await this.googleAuth.getClient();
    }
    return Promise.resolve(this.authClient instanceof Compute);
  }

  /**
 * getIDToken returns a OIDC token from the compute metadata service 
 * that can be used to make authenticated calls to audience
 * @param audience the URL the returned ID token will be used to call.
*/
  public async getIDToken(audience: string): Promise<string> {
    if (await this.isComputeEngineCredential()) {
      return (this.authClient as Compute).fetchIdToken(audience);
    }
    else {
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        'Credentials type should be Compute Engine Credentials.',
      );
    }
  }

  public async getServiceAccountEmail(): Promise<string> {
    if (this.accountId) {
      return Promise.resolve(this.accountId);
    }

    const { client_email: clientEmail } = await this.googleAuth.getCredentials();
    this.accountId = clientEmail ?? '';
    return Promise.resolve(this.accountId);
  }
}

/**
 * Implementation of Credential that uses a service account.
 */
export class ServiceAccountCredential implements Credential {
  /**
   * Creates a new ServiceAccountCredential from the given parameters.
   *
   * @param serviceAccountPathOrObject - Service account json object or path to a service account json file.
   * @param httpAgent - Optional http.Agent to use when calling the remote token server.
   * @param implicit - An optional boolean indicating whether this credential was implicitly discovered from the
   *   environment, as opposed to being explicitly specified by the developer.
   *
   * @constructor
   */
  private constructor(
    private readonly googleAuth: GoogleAuth,
    public readonly projectId: string, public readonly privateKey: string,
    public readonly clientEmail: string,
    private readonly httpAgent?: Agent) {}

  public static async create(serviceAccountPathOrObject: string | object,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    httpAgent?: Agent): Promise<ServiceAccountCredential> {

    const googleAuth = new GoogleAuth({
      scopes: SCOPES,
      keyFile: (typeof serviceAccountPathOrObject === 'string') ?
        serviceAccountPathOrObject : undefined,
    });

    if (typeof serviceAccountPathOrObject === 'object') {
      if (!util.isNonNullObject(serviceAccountPathOrObject)) {
        throw new FirebaseAppError(
          AppErrorCodes.INVALID_CREDENTIAL,
          'Service account must be an object.',
        );
      }
      googleAuth.fromJSON(serviceAccountPathOrObject);
    }

    let projectId: string, credential: CredentialBody;
    try {
      projectId = await googleAuth.getProjectId();
      credential = await googleAuth.getCredentials();
    } catch (error) {
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        'Failed to parse service account json file: ' + error,
      );
    }
    const { private_key: privateKey = '', client_email: clientEmail = '' } = credential;

    let errorMessage;
    if (!util.isNonEmptyString(projectId)) {
      errorMessage = 'Service account object must contain a string "project_id" property.';
    } else if (!util.isNonEmptyString(privateKey)) {
      errorMessage = 'Service account object must contain a string "private_key" property.';
    } else if (!util.isNonEmptyString(clientEmail)) {
      errorMessage = 'Service account object must contain a string "client_email" property.';
    }

    if (typeof errorMessage !== 'undefined') {
      throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, errorMessage);
    }

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const forge = require('node-forge');
    try {
      forge.pki.privateKeyFromPem(privateKey);
    } catch (error) {
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        'Failed to parse private key: ' + error);
    }

    return new ServiceAccountCredential(googleAuth,
      projectId, privateKey, clientEmail, httpAgent);
  }

  public async getAccessToken(): Promise<GoogleOAuthAccessToken> {
    const client = await this.googleAuth.getClient();
    await client.getAccessToken();
    const credentials = client.credentials;
    return populateCredential(credentials);
  }
}

/**
 * Implementation of Credential that gets access tokens from the metadata service available
 * in the Google Cloud Platform. This authenticates the process as the default service account
 * of an App Engine instance or Google Compute Engine machine.
 */
// export class ComputeEngineCredential implements Credential {

//   private readonly httpClient = new HttpClient();
//   private readonly httpAgent?: Agent;
//   private projectId?: string;
//   private accountId?: string;

//   constructor(httpAgent?: Agent) {
//     this.httpAgent = httpAgent;
//   }

//   public getAccessToken(): Promise<GoogleOAuthAccessToken> {
//     const request = this.buildRequest(GOOGLE_METADATA_SERVICE_TOKEN_PATH);
//     return requestAccessToken(this.httpClient, request);
//   }

//   /**
//    * getIDToken returns a OIDC token from the compute metadata service 
//    * that can be used to make authenticated calls to audience
//    * @param audience the URL the returned ID token will be used to call.
//   */
//   public getIDToken(audience: string): Promise<string> {
//     const request = this.buildRequest(`${GOOGLE_METADATA_SERVICE_IDENTITY_PATH}?audience=${audience}`);
//     return requestIDToken(this.httpClient, request);
//   }

//   public getProjectId(): Promise<string> {
//     if (this.projectId) {
//       return Promise.resolve(this.projectId);
//     }

//     const request = this.buildRequest(GOOGLE_METADATA_SERVICE_PROJECT_ID_PATH);
//     return this.httpClient.send(request)
//       .then((resp) => {
//         this.projectId = resp.text!;
//         return this.projectId;
//       })
//       .catch((err) => {
//         const detail: string = (err instanceof HttpError) ? getDetailFromResponse(err.response) : err.message;
//         throw new FirebaseAppError(
//           AppErrorCodes.INVALID_CREDENTIAL,
//           `Failed to determine project ID: ${detail}`);
//       });
//   }

//   public getServiceAccountEmail(): Promise<string> {
//     if (this.accountId) {
//       return Promise.resolve(this.accountId);
//     }

//     const request = this.buildRequest(GOOGLE_METADATA_SERVICE_ACCOUNT_ID_PATH);
//     return this.httpClient.send(request)
//       .then((resp) => {
//         this.accountId = resp.text!;
//         return this.accountId;
//       })
//       .catch((err) => {
//         const detail: string = (err instanceof HttpError) ? getDetailFromResponse(err.response) : err.message;
//         throw new FirebaseAppError(
//           AppErrorCodes.INVALID_CREDENTIAL,
//           `Failed to determine service account email: ${detail}`);
//       });
//   }

//   private buildRequest(urlPath: string): HttpRequestConfig {
//     return {
//       method: 'GET',
//       url: `http://${GOOGLE_METADATA_SERVICE_HOST}${urlPath}`,
//       headers: {
//         'Metadata-Flavor': 'Google',
//       },
//       httpAgent: this.httpAgent,
//     };
//   }
// }

/**
 * Implementation of Credential that gets access tokens from refresh tokens.
 */
export class RefreshTokenCredential implements Credential {

  // private readonly refreshToken: RefreshToken;
  // private readonly httpClient: HttpClient;

  /**
   * Creates a new RefreshTokenCredential from the given parameters.
   *
   * @param refreshTokenPathOrObject - Refresh token json object or path to a refresh token
   *   (user credentials) json file.
   * @param httpAgent - Optional http.Agent to use when calling the remote token server.
   * @param implicit - An optinal boolean indicating whether this credential was implicitly
   *   discovered from the environment, as opposed to being explicitly specified by the developer.
   *
   * @constructor
   */
  constructor(
    private readonly googleAuth: GoogleAuth,
    private readonly httpAgent?: Agent) {}

  public static async create(refreshTokenPathOrObject: string | object,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    httpAgent?: Agent): Promise<RefreshTokenCredential> {

    if (typeof refreshTokenPathOrObject === 'string') {
      try {
        RefreshTokenCredential.validateToken(JSON.parse(fs.readFileSync(refreshTokenPathOrObject, 'utf8')));
      } catch (error) {
        // Throw a nicely formed error message if the file contents cannot be parsed
        throw new FirebaseAppError(
          AppErrorCodes.INVALID_CREDENTIAL,
          'Failed to parse refresh token file: ' + error,
        );
      }
    }

    const googleAuth = new GoogleAuth({
      scopes: SCOPES,
      keyFile: (typeof refreshTokenPathOrObject === 'string') ?
        refreshTokenPathOrObject : undefined,
    });

    if (typeof refreshTokenPathOrObject === 'object') {
      if (!util.isNonNullObject(refreshTokenPathOrObject)) {
        throw new FirebaseAppError(
          AppErrorCodes.INVALID_CREDENTIAL,
          'Refresh token must be an object.',
        );
      }
      RefreshTokenCredential.validateToken(refreshTokenPathOrObject);
      googleAuth.fromJSON(refreshTokenPathOrObject);
    }

    return new RefreshTokenCredential(googleAuth);
  }

  private static validateToken(json: { [key: string]: any }): void {
    const { client_id: clientId, client_secret: clientSecret,
      refresh_token: refreshToken, type } = json;

    let errorMessage;
    if (!util.isNonEmptyString(clientId)) {
      errorMessage = 'Refresh token must contain a "client_id" property.';
    } else if (!util.isNonEmptyString(clientSecret)) {
      errorMessage = 'Refresh token must contain a "client_secret" property.';
    } else if (!util.isNonEmptyString(refreshToken)) {
      errorMessage = 'Refresh token must contain a "refresh_token" property.';
    } else if (!util.isNonEmptyString(type)) {
      errorMessage = 'Refresh token must contain a "type" property.';
    }

    if (typeof errorMessage !== 'undefined') {
      throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, errorMessage);
    }
  }

  public async getAccessToken(): Promise<GoogleOAuthAccessToken> {
    const client = await this.googleAuth.getClient();
    await client.getAccessToken();
    const credentials = client.credentials;
    return populateCredential(credentials);
    // const postData =
    //   'client_id=' + this.refreshToken.clientId + '&' +
    //   'client_secret=' + this.refreshToken.clientSecret + '&' +
    //   'refresh_token=' + this.refreshToken.refreshToken + '&' +
    //   'grant_type=refresh_token';
    // const request: HttpRequestConfig = {
    //   method: 'POST',
    //   url: `https://${REFRESH_TOKEN_HOST}${REFRESH_TOKEN_PATH}`,
    //   headers: {
    //     'Content-Type': 'application/x-www-form-urlencoded',
    //   },
    //   data: postData,
    //   httpAgent: this.httpAgent,
    // };
    // return requestAccessToken(this.httpClient, request);
  }
}

// class RefreshToken {

//   public readonly clientId: string;
//   public readonly clientSecret: string;
//   public readonly refreshToken: string;
//   public readonly type: string;

//   /*
//    * Tries to load a RefreshToken from a path. Throws if the path doesn't exist or the
//    * data at the path is invalid.
//    */
//   public static fromPath(filePath: string): RefreshToken {
//     try {
//       return new RefreshToken(JSON.parse(fs.readFileSync(filePath, 'utf8')));
//     } catch (error) {
//       // Throw a nicely formed error message if the file contents cannot be parsed
//       throw new FirebaseAppError(
//         AppErrorCodes.INVALID_CREDENTIAL,
//         'Failed to parse refresh token file: ' + error,
//       );
//     }
//   }

//   constructor(json: object) {
//     copyAttr(this, json, 'clientId', 'client_id');
//     copyAttr(this, json, 'clientSecret', 'client_secret');
//     copyAttr(this, json, 'refreshToken', 'refresh_token');
//     copyAttr(this, json, 'type', 'type');

//     let errorMessage;
//     if (!util.isNonEmptyString(this.clientId)) {
//       errorMessage = 'Refresh token must contain a "client_id" property.';
//     } else if (!util.isNonEmptyString(this.clientSecret)) {
//       errorMessage = 'Refresh token must contain a "client_secret" property.';
//     } else if (!util.isNonEmptyString(this.refreshToken)) {
//       errorMessage = 'Refresh token must contain a "refresh_token" property.';
//     } else if (!util.isNonEmptyString(this.type)) {
//       errorMessage = 'Refresh token must contain a "type" property.';
//     }

//     if (typeof errorMessage !== 'undefined') {
//       throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, errorMessage);
//     }
//   }
// }


/**
 * Implementation of Credential that uses impersonated service account.
 */
export class ImpersonatedServiceAccountCredential implements Credential {

  private readonly impersonatedServiceAccount: ImpersonatedServiceAccount;
  private readonly httpClient: HttpClient;

  /**
   * Creates a new ImpersonatedServiceAccountCredential from the given parameters.
   *
   * @param impersonatedServiceAccountPathOrObject - Impersonated Service account json object or
   * path to a service account json file.
   * @param httpAgent - Optional http.Agent to use when calling the remote token server.
   * @param implicit - An optional boolean indicating whether this credential was implicitly
   *   discovered from the environment, as opposed to being explicitly specified by the developer.
   *
   * @constructor
   */
  constructor(
    impersonatedServiceAccountPathOrObject: string | object,
    private readonly httpAgent?: Agent,
    readonly implicit: boolean = false) {

    this.impersonatedServiceAccount = (typeof impersonatedServiceAccountPathOrObject === 'string') ?
      ImpersonatedServiceAccount.fromPath(impersonatedServiceAccountPathOrObject)
      : new ImpersonatedServiceAccount(impersonatedServiceAccountPathOrObject);
    this.httpClient = new HttpClient();
  }

  public getAccessToken(): Promise<GoogleOAuthAccessToken> {
    const postData =
      'client_id=' + this.impersonatedServiceAccount.clientId + '&' +
      'client_secret=' + this.impersonatedServiceAccount.clientSecret + '&' +
      'refresh_token=' + this.impersonatedServiceAccount.refreshToken + '&' +
      'grant_type=refresh_token';
    const request: HttpRequestConfig = {
      method: 'POST',
      url: `https://${REFRESH_TOKEN_HOST}${REFRESH_TOKEN_PATH}`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: postData,
      httpAgent: this.httpAgent,
    };
    return requestAccessToken(this.httpClient, request);
  }
}

/**
 * A struct containing the properties necessary to use impersonated service account JSON credentials.
 */
class ImpersonatedServiceAccount {

  public readonly clientId: string;
  public readonly clientSecret: string;
  public readonly refreshToken: string;
  public readonly type: string;

  /*
   * Tries to load a ImpersonatedServiceAccount from a path. Throws if the path doesn't exist or the
   * data at the path is invalid.
   */
  public static fromPath(filePath: string): ImpersonatedServiceAccount {
    try {
      return new ImpersonatedServiceAccount(JSON.parse(fs.readFileSync(filePath, 'utf8')));
    } catch (error) {
      // Throw a nicely formed error message if the file contents cannot be parsed
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        'Failed to parse impersonated service account file: ' + error,
      );
    }
  }

  constructor(json: object) {
    const sourceCredentials = (json as { [key: string]: any })['source_credentials']
    if (sourceCredentials) {
      copyAttr(this, sourceCredentials, 'clientId', 'client_id');
      copyAttr(this, sourceCredentials, 'clientSecret', 'client_secret');
      copyAttr(this, sourceCredentials, 'refreshToken', 'refresh_token');
      copyAttr(this, sourceCredentials, 'type', 'type');
    }

    let errorMessage;
    if (!util.isNonEmptyString(this.clientId)) {
      errorMessage = 'Impersonated Service Account must contain a "source_credentials.client_id" property.';
    } else if (!util.isNonEmptyString(this.clientSecret)) {
      errorMessage = 'Impersonated Service Account must contain a "source_credentials.client_secret" property.';
    } else if (!util.isNonEmptyString(this.refreshToken)) {
      errorMessage = 'Impersonated Service Account must contain a "source_credentials.refresh_token" property.';
    } else if (!util.isNonEmptyString(this.type)) {
      errorMessage = 'Impersonated Service Account must contain a "source_credentials.type" property.';
    }

    if (typeof errorMessage !== 'undefined') {
      throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, errorMessage);
    }
  }
}

/**
 * Checks if the given credential was loaded via the application default credentials mechanism.
 *
 * @param credential - The credential instance to check.
 */
export function isApplicationDefault(credential?: Credential): boolean {
  return credential instanceof ApplicationDefaultCredential;
}

export function getApplicationDefault(httpAgent?: Agent): Credential {

  return new ApplicationDefaultCredential(httpAgent);
  /*
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    return credentialFromFile(process.env.GOOGLE_APPLICATION_CREDENTIALS, httpAgent, false)!;
  }

  // It is OK to not have this file. If it is present, it must be valid.
  if (GCLOUD_CREDENTIAL_PATH) {
    const credential =  credentialFromFile(GCLOUD_CREDENTIAL_PATH, httpAgent, true);
    if (credential) return credential
  }

  return new ComputeEngineCredential(httpAgent);*/
}

/**
 * Copies the specified property from one object to another.
 *
 * If no property exists by the given "key", looks for a property identified by "alt", and copies it instead.
 * This can be used to implement behaviors such as "copy property myKey or my_key".
 *
 * @param to - Target object to copy the property into.
 * @param from - Source object to copy the property from.
 * @param key - Name of the property to copy.
 * @param alt - Alternative name of the property to copy.
 */
function copyAttr(to: { [key: string]: any }, from: { [key: string]: any }, key: string, alt: string): void {
  const tmp = from[key] || from[alt];
  if (typeof tmp !== 'undefined') {
    to[key] = tmp;
  }
}

/**
 * Populate GoogleOAuthAccessToken credentials from google-auth-library Credentials type.
 */
function populateCredential(credentials?: GoogleAuthCredentials): GoogleOAuthAccessToken {
  const accessToken = credentials?.access_token;
  const expiryDate = credentials?.expiry_date;

  if (typeof accessToken !== 'string')
    throw new FirebaseAppError(
      AppErrorCodes.INVALID_CREDENTIAL,
      'Failed to parse Google auth credential: access_token must be a non empty string.',
    );
  if (typeof expiryDate !== 'number')
    throw new FirebaseAppError(
      AppErrorCodes.INVALID_CREDENTIAL,
      'Failed to parse Google auth credential: Invalid expiry_date.',
    );

  return {
    ...credentials,
    access_token: accessToken,
    // inverse operation of following
    // https://github.com/googleapis/google-auth-library-nodejs/blob/5ed910513451c82e2551777a3e2212964799ef8e/src/auth/baseexternalclient.ts#L446-L446
    expires_in: Math.floor((expiryDate - new Date().getTime()) / 1000),
  }
}

/**
 * Obtain a new OAuth2 token by making a remote service call.
 */
function requestAccessToken(client: HttpClient, request: HttpRequestConfig): Promise<GoogleOAuthAccessToken> {
  return client.send(request).then((resp) => {
    const json = resp.data;
    if (!json.access_token || !json.expires_in) {
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        `Unexpected response while fetching access token: ${JSON.stringify(json)}`,
      );
    }
    return json;
  }).catch((err) => {
    throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, getErrorMessage(err));
  });
}

// /**
//  * Obtain a new OIDC token by making a remote service call.
//  */
// function requestIDToken(client: HttpClient, request: HttpRequestConfig): Promise<string> {
//   return client.send(request).then((resp) => {
//     if (!resp.text) {
//       throw new FirebaseAppError(
//         AppErrorCodes.INVALID_CREDENTIAL,
//         'Unexpected response while fetching id token: response.text is undefined',
//       );
//     }
//     return resp.text;
//   }).catch((err) => {
//     throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, getErrorMessage(err));
//   });
// }

/**
 * Constructs a human-readable error message from the given Error.
 */
function getErrorMessage(err: Error): string {
  const detail: string = (err instanceof HttpError) ? getDetailFromResponse(err.response) : err.message;
  return `Error fetching access token: ${detail}`;
}

/**
 * Extracts details from the given HTTP error response, and returns a human-readable description. If
 * the response is JSON-formatted, looks up the error and error_description fields sent by the
 * Google Auth servers. Otherwise returns the entire response payload as the error detail.
 */
function getDetailFromResponse(response: HttpResponse): string {
  if (response.isJson() && response.data.error) {
    const json = response.data;
    let detail = json.error;
    if (json.error_description) {
      detail += ' (' + json.error_description + ')';
    }
    return detail;
  }
  return response.text || 'Missing error payload';
}

/*function credentialFromFile(filePath: string, httpAgent?: Agent, ignoreMissing?: boolean): Credential | null {
  const credentialsFile = readCredentialFile(filePath, ignoreMissing);
  if (typeof credentialsFile !== 'object' || credentialsFile === null) {
    if (ignoreMissing) { return null; }
    throw new FirebaseAppError(
      AppErrorCodes.INVALID_CREDENTIAL,
      'Failed to parse contents of the credentials file as an object',
    );
  }

  if (credentialsFile.type === 'service_account') {
    return new ServiceAccountCredential(credentialsFile, httpAgent, true);
  }

  if (credentialsFile.type === 'authorized_user') {
    return new RefreshTokenCredential(credentialsFile, httpAgent, true);
  }

  if (credentialsFile.type === 'impersonated_service_account') {
    return new ImpersonatedServiceAccountCredential(credentialsFile, httpAgent, true)
  }

  throw new FirebaseAppError(
    AppErrorCodes.INVALID_CREDENTIAL,
    'Invalid contents in the credentials file',
  );
}*/
/*
function readCredentialFile(filePath: string, ignoreMissing?: boolean): {[key: string]: any} | null {
  let fileText: string;
  try {
    fileText = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    if (ignoreMissing) {
      return null;
    }

    throw new FirebaseAppError(
      AppErrorCodes.INVALID_CREDENTIAL,
      `Failed to read credentials from file ${filePath}: ` + error,
    );
  }

  try {
    return JSON.parse(fileText);
  } catch (error) {
    throw new FirebaseAppError(
      AppErrorCodes.INVALID_CREDENTIAL,
      'Failed to parse contents of the credentials file as an object: ' + error,
    );
  }
}
*/
