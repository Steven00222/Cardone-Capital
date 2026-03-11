import bcrypt from 'bcryptjs';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/api/register' && request.method === 'POST') {
      const { email, password } = await request.json();
      const existing = await env.USERS_KV.get(email);
      if (existing) return new Response('Email already registered', { status: 400 });
      const hash = bcrypt.hashSync(password, 10);
      await env.USERS_KV.put(email, JSON.stringify({
        email,
        passwordHash: hash,
        balances: { BTC: 0, ETH: 0, USDT_TRX: 0, USDT_ERC: 0 },
        wallets: { BTC: '', ETH: '', USDT_TRX: '', USDT_ERC: '' }
      }));
      return new Response('Registered');
    }

    if (path === '/api/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      const data = await env.USERS_KV.get(email);
      if (!data) return new Response('User not found', { status: 404 });
      const user = JSON.parse(data);
      if (!bcrypt.compareSync(password, user.passwordHash)) return new Response('Wrong password', { status: 403 });
      return new Response(JSON.stringify(user), { headers: { 'Content-Type': 'application/json' } });
    }

    if (path.startsWith('/api/admin')) {
      const adminKey = url.searchParams.get('admin');
      if (adminKey !== env.ADMIN_KEY) return new Response('Unauthorized', { status: 403 });

      if (request.method === 'POST') {
        const { email, balances, wallets, notes } = await request.json();
        if (email) {
          const user = JSON.parse(await env.USERS_KV.get(email));
          if (!user) return new Response('User not found', { status: 404 });
          if (balances) user.balances = balances;
          if (wallets) user.wallets = wallets;
          await env.USERS_KV.put(email, JSON.stringify(user));
        }
        if (notes) await env.SETTINGS_KV.put('notes', notes);
        return new Response('Updated');
      }

      if (request.method === 'GET') {
        const usersList = [];
        const list = await env.USERS_KV.list();
        for (const key of list.keys) {
          const u = JSON.parse(await env.USERS_KV.get(key.name));
          usersList.push(u);
        }
        const notes = await env.SETTINGS_KV.get('notes');
        return new Response(JSON.stringify({ users: usersList, notes }), { headers: { 'Content-Type': 'application/json' } });
      }
    }

    return new Response('Not Found', { status: 404 });
  }
};
