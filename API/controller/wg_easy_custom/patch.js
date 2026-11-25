'use strict';
// Build-time patch against the pinned wg-easy 13 image; fail on source drift.
const fs = require('fs');
function replaceOnce(path, needle, replacement) {
  const src = fs.readFileSync(path, 'utf8');
  if (src.split(needle).length !== 2) throw new Error(`Unexpected source in ${path}`);
  fs.writeFileSync(path, src.replace(needle, replacement));
}
const wg = '/app/lib/WireGuard.js';
const server = '/app/lib/Server.js';
const methods = `
  validateExternalKey(publicKey) {
    if (typeof publicKey !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(publicKey)) throw new Error('Invalid public key');
    const raw = Buffer.from(publicKey, 'base64');
    if (raw.length !== 32 || raw.toString('base64') !== publicKey || raw.every((b) => b === 0)) throw new Error('Invalid public key');
  }

  async createExternalClient({ name, publicKey }) {
    if (typeof name !== 'string' || !/^netshield-[1-9][0-9]*-[a-f0-9]{32}$/.test(name)) throw new Error('Invalid name');
    this.validateExternalKey(publicKey);
    const config = await this.getConfig();
    if (Object.values(config.clients).some((c) => c.name === name || c.publicKey === publicKey)) throw new Error('Duplicate client');
    let address;
    for (let i = 2; i < 255; i++) {
      const candidate = WG_DEFAULT_ADDRESS.replace('x', i);
      if (!Object.values(config.clients).some((c) => c.address === candidate)) { address = candidate; break; }
    }
    if (!address) throw new Error('Maximum number of clients reached');
    const id = crypto.randomUUID();
    config.clients[id] = { id, name, address, publicKey, createdAt: new Date(), updatedAt: new Date(), enabled: true };
    await this.saveConfig();
  }

  async setExternalPublicKey({ clientId, publicKey }) {
    this.validateExternalKey(publicKey);
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client || !client.enabled || !/^netshield-[1-9][0-9]*-[a-f0-9]{32}$/.test(client.name)) throw new Error('Invalid client');
    if (Object.entries(config.clients).some(([id, c]) => id !== clientId && c.publicKey === publicKey)) throw new Error('Duplicate public key');
    client.publicKey = publicKey;
    delete client.privateKey;
    delete client.preSharedKey;
    client.updatedAt = new Date();
    await this.saveConfig();
  }

`;
replaceOnce(wg, '  async createClient({ name }) {', methods + '  async createClient({ name }) {');
const route = `      .post('/api/wireguard/client-external', defineEventHandler(async (event) => {
        const { name, publicKey } = await readBody(event);
        await WireGuard.createExternalClient({ name, publicKey });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/public-key', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const { publicKey } = await readBody(event);
        await WireGuard.setExternalPublicKey({ clientId, publicKey });
        return { success: true };
      }))
`;
replaceOnce(server, "      .post('/api/wireguard/client', defineEventHandler", route + "      .post('/api/wireguard/client', defineEventHandler");
