import { encryptPassword, decryptPassword, verifyPassword } from "./phaser.ts";
import { assert, assertEquals } from "@std/assert";

const privateKey = "your-very-strong-private-key";
const password = "my-secret-password";

const phase = await encryptPassword(password, privateKey);

Deno.test("decrypt", async () => {
  console.log("Encrypted:", phase);
  const decrypted = await decryptPassword(phase, privateKey);
  assertEquals(decrypted, password);
});
Deno.test("verify", async () => {
  assert(await verifyPassword("my-secret-password", phase, privateKey));
});
