import { AwsGateway } from '../../connector-worker/src/aws.js';
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  APIGatewayRequestAuthorizerEventV2,
} from 'aws-lambda';
import { createApp } from './app.js';
import { database, Store } from '../../../packages/shared-utils/src/store.js';

function application() {
  if (!process.env.IDENTITY_TABLE || !process.env.APP_ORIGIN)
    throw new Error('IDENTITY_TABLE and APP_ORIGIN are required');
  return createApp(new Store(database(), process.env.IDENTITY_TABLE), {
    origin: process.env.APP_ORIGIN,
    local: false,
    encryptionKey: process.env.MFA_ENCRYPTION_KEY,
    cloud: process.env.CLOUDSENTINEL_AWS_PRINCIPAL_ARN
      ? { principalArn: process.env.CLOUDSENTINEL_AWS_PRINCIPAL_ARN, gateway: new AwsGateway() }
      : undefined,
  });
}
let app: ReturnType<typeof application> | undefined;
const getApp = () => (app ??= application());
export async function handler(
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> {
  const headers = new Headers();
  for (const [key, value] of Object.entries(event.headers))
    if (value !== undefined) headers.set(key, value);
  if (event.cookies) headers.set('cookie', event.cookies.join('; '));
  const response = await (
    await getApp()
  ).handle(
    new Request(
      `${process.env.APP_ORIGIN}${event.rawPath}${event.rawQueryString ? `?${event.rawQueryString}` : ''}`,
      {
        method: event.requestContext.http.method,
        headers,
        body: event.body
          ? event.isBase64Encoded
            ? Buffer.from(event.body, 'base64').toString()
            : event.body
          : undefined,
      },
    ),
    event.requestContext.http.sourceIp,
  );
  const resultHeaders = Object.fromEntries(response.headers);
  const setCookie = resultHeaders['set-cookie'];
  delete resultHeaders['set-cookie'];
  return {
    statusCode: response.status,
    headers: resultHeaders,
    body: await response.text(),
    ...(setCookie ? { cookies: [setCookie] } : {}),
  };
}
// HTTP API simple-response authorizer. Configure authorizerResultTtlInSeconds = 0.
// Services still validate sessions and perform action/object authorization themselves.
export async function authorizer(event: APIGatewayRequestAuthorizerEventV2) {
  try {
    const headers = new Headers();
    for (const [key, value] of Object.entries(event.headers ?? {}))
      if (value) headers.set(key, value);
    if (event.cookies) headers.set('cookie', event.cookies.join('; '));
    const context = await (
      await getApp()
    ).validate(new Request(`${process.env.APP_ORIGIN}/api/auth/me`, { headers }));
    return { isAuthorized: true, context };
  } catch {
    return { isAuthorized: false };
  }
}
