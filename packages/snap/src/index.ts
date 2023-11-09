import type { OnRpcRequestHandler } from "@metamask/snaps-types";
import { panel, text, heading, divider } from "@metamask/snaps-ui";
//import { idOS } from "@idos-network/idos-sdk";
import scrypt from "scrypt-js";
import nacl from "tweetnacl";
import * as Base64Codec from "@stablelib/base64";
import * as Utf8Codec from "@stablelib/utf8";

const panelHeader = (origin) => [
  heading("idOS Secure Enclave"),
  text(`You"re using **${origin}**`),
  divider(),
];

const getState = async () => await snap.request({
  method: "snap_manageState",
  params: { operation: "get" },
}) || {};

const addToState = async (newState = {}) => {
  const oldState = await getState();

  return snap.request({
    method: "snap_manageState",
    params: {
      operation: "update",
      newState: { ...oldState, ...newState },
    },
  });
};

const clearState = async () => await snap.request({
  method: 'snap_manageState',
  params: { operation: 'clear' },
});

const storage = async (payload = {}) => {
  const toStore = Object.entries(payload).reduce((res, [k, v]) => (
      !!v ? Object.assign(res, {[k]: v}) : res
    ), {})
  await addToState(toStore);

  let { humanId, signerAddress, signerPublicKey, keyPair } = await getState();

  const encryptionPublicKey = keyPair?.publicKey;

  return { storage: {
    humanId,
    signerAddress,
    signerPublicKey,
    encryptionPublicKey,
  }};
};

const init = async (requestParams, origin) => {
  let { keyPair, humanId } = await getState();
  let publicKey;

  if (keyPair) {
    publicKey = Uint8Array.from(Object.values(keyPair.publicKey));
  } else {
    const password = await snap.request({
      method: "snap_dialog",
      params: {
        type: "prompt",
        content: panel([
          ...panelHeader(origin),
          text(`Please enter your idOS password`),
          text(`It will take a few seconds to digest.`),
        ]),
        placeholder: "idOS password",
      },
    });

    const secretKey = await scrypt.scrypt(
      Utf8Codec.encode(password.normalize("NFKC")),
      Utf8Codec.encode(humanId),
      16384, 8, 1, 32,
    );

    keyPair = nacl.box.keyPair.fromSecretKey(secretKey);

    await addToState({ keyPair });

    publicKey = keyPair.publicKey;
  }

  return { publicKey: Base64Codec.encode(publicKey) };
};

const encrypt = async ({ message, receiverPublicKey }) => {
  if (!message) throw new Error("encrypt: no message");
  message = Utf8Codec.encode(message)

  const { keyPair } = await getState();
  if (!keyPair) throw new Error("encrypt: no keypair");

  let { publicKey, secretKey } = keyPair;
  publicKey = Uint8Array.from(Object.values(publicKey));
  secretKey = Uint8Array.from(Object.values(secretKey));

  receiverPublicKey &&= Base64Codec.decode(receiverPublicKey);
  receiverPublicKey ||= publicKey;

  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const encrypted = nacl.box(message, nonce, receiverPublicKey, secretKey);
  if (!encrypted) throw new Error("encrypt: encryption failed");

  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce, 0);
  fullMessage.set(encrypted, nonce.length);

  return { encrypted: Base64Codec.encode(fullMessage) };
};

const decrypt = async ({ message: fullMessage, senderPublicKey }) => {
  if (!fullMessage) throw new Error("decrypt: no message");
  fullMessage = Uint8Array.from(Object.values(fullMessage))

  const { keyPair } = await getState();
  if (!keyPair) throw new Error("decrypt: no keypair");

  let { publicKey, secretKey } = keyPair;
  publicKey = Uint8Array.from(Object.values(publicKey))
  secretKey = Uint8Array.from(Object.values(secretKey))

  senderPublicKey &&= Uint8Array.from(Object.values(senderPublicKey));
  senderPublicKey ||= publicKey;

  const nonce = fullMessage.slice(0, nacl.box.nonceLength);
  const message = fullMessage.slice(nacl.box.nonceLength, fullMessage.length);
  const decrypted = nacl.box.open(message, nonce, senderPublicKey, secretKey);
  if (!decrypted) throw new Error("decrypt: decryption failed");

  return { decrypted };
};

const reset = async () => await clearState();

const confirm = async({ message }, origin) => {
  const confirmed = snap.request({
    method: "snap_dialog",
    params: {
      type: "confirmation",
      content: panel([
        ...panelHeader(origin),
        text("**This dapp is asking you:**"),
        text(`_${message}_`),
      ]),
    },
  });

  return { confirmed };
};

export const onRpcRequest: OnRpcRequestHandler = async ({ origin, request }) => {
  console.group(`onRpcRequest: ${request.method}`);
  console.log({ origin });
  console.log({ params: request.params });

  switch (request.method) {
    case "storage":
      return storage(request.params)
        .then(result => (console.log({ result }), result))
        .then(({ storage }) => JSON.stringify(storage))
        .catch(console.warn)
        .finally(console.groupEnd);

    case "init":
      return init(request.params, origin)
        .then(result => (console.log({ result }), result))
        .then(({ publicKey }) => publicKey)
        .catch(console.warn)
        .finally(console.groupEnd);

    case "encrypt":
      if (!request.params.message) return { error: "no message" };

      return encrypt(request.params)
        .then(result => (console.log({ result }), result))
        .then(({ encrypted }) => encrypted)
        .catch(console.warn)
        .finally(console.groupEnd);

    case "decrypt":
      if (!request.params.message) return { error: "no message" };

      return decrypt(request.params)
        .then(result => (console.log({ result }), result))
        .then(({ decrypted }) => decrypted)
        .catch(console.warn)
        .finally(console.groupEnd);

    case "reset":
      return reset()
        .then(result => (console.log({ result }), result))
        .catch(console.warn)
        .finally(console.groupEnd);

    case "confirm":
      return confirm(request.params, origin)
        .then(result => (console.log({ result}), result))
        .then(({ confirmed }) => confirmed)
        .catch(console.warn)
        .finally(console.groupEnd);

    default:
      throw new Error("Unexpected request.");
  }
};
