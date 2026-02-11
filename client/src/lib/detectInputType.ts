export type InputType = "ip" | "domain" | "url";

export function detectInputType(input: string): InputType {
  const value = input.trim().toLowerCase();

  // URL (http / https)
  if (/^https?:\/\//.test(value)) {
    return "url";
  }

  // IPv4 address
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return "ip";
  }

  // Everything else → domain
  return "domain";
}
