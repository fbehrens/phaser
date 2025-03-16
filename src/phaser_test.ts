import { phase, dephase, verifyPassword } from "./phaser.ts";
import { assert, assertEquals } from "@std/assert";

const privateKey = "your-very-strong-private-key";
const password = "my-secret-password";

const p = await phase(password, privateKey);

Deno.test("decrypt", async () => {
  console.log("Encrypted:", p);
  const decrypted = await dephase(p, privateKey);
  assertEquals(decrypted, password);
});
Deno.test("verify", async () => {
  assert(await verifyPassword("my-secret-password", p, privateKey));
});
