import { AppError } from "../errors.js";

const secretFieldPattern = /(^|_)(api_?key|access_?token|refresh_?token|password|passwd|private_?key|client_?secret|secret)($|_)/i;
const authorityImpersonationFields = new Set([
  "enterprise_fact",
  "authoritative",
  "authority_decision",
  "execution_permit",
  "approved",
]);

export function collectFieldPaths(
  value: unknown,
  predicate: (key: string) => boolean,
  prefix = "",
): string[] {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectFieldPaths(entry, predicate, `${prefix}[${index}]`),
    );
  }

  return Object.entries(value as Record<string, unknown>).flatMap(([key, entry]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return [
      ...(predicate(key) ? [path] : []),
      ...collectFieldPaths(entry, predicate, path),
    ];
  });
}

export function assertNoSecretFields(value: unknown): void {
  const paths = collectFieldPaths(value, (key) => secretFieldPattern.test(key));
  if (paths.length > 0) {
    throw new AppError(
      422,
      "D4_SECRET_REJECTED",
      "D4 secret values must never enter the middleware.",
      { paths },
    );
  }
}

export function findAIResultQuarantineReasons(value: unknown): string[] {
  const secretPaths = collectFieldPaths(value, (key) => secretFieldPattern.test(key));
  const authorityPaths = collectFieldPaths(value, (key) =>
    authorityImpersonationFields.has(key.toLowerCase()),
  );
  return [
    ...secretPaths.map((path) => `secret-like field: ${path}`),
    ...authorityPaths.map((path) => `authority impersonation field: ${path}`),
  ];
}
