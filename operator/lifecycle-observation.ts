/** Authority storage could not be inspected; no authority-state fields are asserted. */
export const UNAVAILABLE_AUTHORITY_OBSERVATION: Readonly<{ version: 1; status: "UNAVAILABLE"; receipt?: never }> =
  Object.freeze({ version: 1, status: "UNAVAILABLE" } as const);
export type UnavailableAuthorityObservation = typeof UNAVAILABLE_AUTHORITY_OBSERVATION;
