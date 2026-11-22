export type SafeLog = {
  requestId: string;
  method: string;
  status: number;
  durationMs: number;
  event: 'request.completed' | 'request.failed';
};
export function log(event: SafeLog) {
  console.log(JSON.stringify(event));
}
