// Preloaded only in the real-process diagnostic test. Fail one asynchronous reply
// after its request was handled, leaving the origin and launcher lifetime pipe live.
const send = process.send.bind(process);
process.send = (message, ...args) => {
  if (message.reply?.type !== "origin-stats") return send(message, ...args);
  process.send = send;
  const callback = args.at(-1);
  setImmediate(() => {
    callback(new Error("diagnostic reply delivery failed"));
    send({ id: message.id, injectedFailure: true });
  });
  return true;
};
