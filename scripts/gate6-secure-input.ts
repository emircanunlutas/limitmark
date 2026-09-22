// Gate 6A: the one place a Gate 6 R2 secret ever touches process memory
// during capture. Reads exactly one field from an interactive TTY with no
// echo at all (not even a mask character, so terminal scrollback never shows
// even the length) and no history of any kind. Refuses outright when stdin
// is not a real TTY -- there is no non-interactive fallback in the reviewed
// tool, so a secret can never arrive through argv, an environment variable,
// a piped file, or shell redirection. tests/gate6-credential-capture.test.ts
// exercises the CLI that calls this through an esbuild-substituted synthetic
// version of this exact module (mirroring the existing r2-transport
// substitution in tests/workers/support/i3b-cli-result-harness.ts), so the
// real TTY code path below is never exercised by an automated test -- it can
// only be exercised by an interactive operator.

const MAX_FIELD_LENGTH = 512;

type MinimalTtyInput = {
  isTTY?: boolean;
  setRawMode(mode: boolean): unknown;
  resume(): unknown;
  pause(): unknown;
  on(event: "data", listener: (chunk: Buffer) => void): unknown;
  removeListener(event: "data", listener: (chunk: Buffer) => void): unknown;
};
type MinimalTtyOutput = { write(chunk: string): unknown };

/** Reads one line from an interactive TTY with no echo. Enter finishes,
 * Backspace/Delete edits, Ctrl+C aborts cleanly (never returns a partial
 * value). Never logs, never echoes, never persists. */
export async function readMaskedField(label: string, input: MinimalTtyInput = process.stdin,
  output: MinimalTtyOutput = process.stdout): Promise<string> {
  if (!input.isTTY) throw new Error("gate6-capture-requires-interactive-tty");
  output.write(`${label} (input hidden, Enter to confirm): `);
  return new Promise<string>((resolvePromise, reject) => {
    let value = "";
    let settled = false;
    const onData = (chunk: Buffer) => {
      for (let index = 0; index < chunk.length; index++) {
        const byte = chunk[index];
        if (byte === 0x0d || byte === 0x0a) { finish(); return; }
        if (byte === 0x03) { finish(new Error("gate6-capture-aborted")); return; }
        if (byte === 0x7f || byte === 0x08) { if (value.length) value = value.slice(0, -1); continue; }
        if (byte < 0x20) continue;
        if (value.length < MAX_FIELD_LENGTH) value += String.fromCharCode(byte);
      }
    };
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      input.setRawMode(false);
      input.pause();
      input.removeListener("data", onData);
      output.write("\n");
      if (error) reject(error); else resolvePromise(value);
    };
    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}
