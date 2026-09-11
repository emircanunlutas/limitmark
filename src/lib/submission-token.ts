export const submissionTokenField = "submissionToken";
const submissionTokenPattern = /^[A-Za-z0-9_-]{43}$/;

export function isSubmissionToken(value: unknown): value is string {
  return typeof value === "string" && submissionTokenPattern.test(value);
}

export function readSubmissionToken(formData: FormData): string | null {
  const values = formData.getAll(submissionTokenField);
  return values.length === 1 && isSubmissionToken(values[0]) ? values[0] : null;
}
