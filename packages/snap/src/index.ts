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

const setState = async (newState = {}, { clear = false } = {}) => {
  const oldState = clear ? {} : await getState();

  return snap.request({
    method: "snap_manageState",
    params: {
      operation: "update",
      newState: { ...oldState, ...newState },
    },
  });
};

const snapPrompt = async ({ origin = "unknown" }) => {
  return snap.request({
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
  })
};

const init = async ({ humanId }, origin) => {
  let { keyPair } = await getState();

  let { publicKey } = keyPair;
  publicKey &&= Uint8Array.from(Object.values(keyPair.publicKey));

  if (!keyPair) {
    const password = await snapPrompt({ origin });
    const secretKey = await scrypt.scrypt(
      Utf8Codec.encode(password.normalize("NFKC")),
      Utf8Codec.encode(humanId),
      16384, 8, 1, 32,
    );

    keyPair = nacl.box.keyPair.fromSecretKey(secretKey);

    void await setState({ humanId, keyPair });

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
  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce, 0);
  fullMessage.set(encrypted, nonce.length);

  if (!encrypted) throw new Error("encrypt: encryption failed");

  return { encrypted: Base64Codec.encode(fullMessage) };
};

const decrypt = async ({ message: fullMessage, senderPublicKey }) => {
  if (!fullMessage) throw new Error("decrypt: no message");
  fullMessage = Base64Codec.decode(fullMessage);

  const { keyPair } = await getState();
  if (!keyPair) throw new error("decrypt: no keypair");

  let { publicKey, secretKey } = keyPair;
  publicKey = Uint8Array.from(Object.values(publicKey))
  secretKey = Uint8Array.from(Object.values(secretKey))

  senderPublicKey &&= Base64Codec.decode(senderPublicKey);
  senderPublicKey ||= publicKey;

  const nonce = fullMessage.slice(0, nacl.box.nonceLength);
  const message = fullMessage.slice(nacl.box.nonceLength, fullMessage.length);
  const decrypted = nacl.box.open(message, nonce, publicKey, secretKey);

  if (!decrypted) throw new Error("decrypt: decryption failed");

  return { decrypted: Utf8Codec.decode(decrypted) };
};

export const onRpcRequest: OnRpcRequestHandler = async ({ origin, request }) => {
  switch (request.method) {
    case "init":
      if (!request.params.humanId) return { error: "no human ID" };

      return init(request.params, origin)
        .then(({ publicKey }) => publicKey)
        .catch(console.warn);

    case "encrypt":
      if (!request.params.message) return { error: "no message" };

      return encrypt(request.params)
        .then(({ encrypted }) => encrypted)
        .catch(console.warn);

    case "decrypt":
      if (!request.params.message) return { error: "no message" };

      return decrypt(request.params)
        .then(({ decrypted }) => decrypted)
        .catch(console.warn);

    default:
      throw new Error("Unexpected request.");
  }
};
