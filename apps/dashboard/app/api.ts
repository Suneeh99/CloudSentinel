export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...options,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'content-type': 'application/json', ...options.headers },
  });
  const value = await response.json();
  if (!response.ok)
    throw new ApiError(response.status, value.error ?? 'The request failed. Try again.');
  return value as T;
}
