import { createClient } from 'npm:@supabase/supabase-js@2'

const allowedOrigins = new Set([
  'https://futari-no-saifu-web.vercel.app',
  'http://localhost:3000',
])

function response(body: Record<string, unknown>, status: number, origin: string | null) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Vary': 'Origin',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  }
  if (origin && allowedOrigins.has(origin)) headers['Access-Control-Allow-Origin'] = origin
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers })
}

function keyFromEnv(name: string, fallback?: string) {
  const raw = Deno.env.get(name)
  if (!raw) return fallback
  try {
    const keys = JSON.parse(raw)
    return keys.default || Object.values(keys)[0] as string
  } catch {
    return raw
  }
}

Deno.serve(async (req) => {
  const origin = req.headers.get('origin')
  if (origin && !allowedOrigins.has(origin)) return response({ error: 'origin_not_allowed' }, 403, null)
  if (req.method === 'OPTIONS') return response({}, 204, origin)
  if (req.method !== 'POST') return response({ error: 'method_not_allowed' }, 405, origin)

  const authorization = req.headers.get('authorization') || ''
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1]
  if (!token) return response({ error: 'not_authenticated' }, 401, origin)

  const url = Deno.env.get('SUPABASE_URL')
  const publishableKey = keyFromEnv('SUPABASE_PUBLISHABLE_KEYS', Deno.env.get('SUPABASE_ANON_KEY'))
  const secretKey = keyFromEnv('SUPABASE_SECRET_KEYS', Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))
  if (!url || !publishableKey || !secretKey) return response({ error: 'server_not_configured' }, 500, origin)

  let password: unknown
  try {
    password = (await req.json()).password
  } catch {
    return response({ error: 'invalid_request' }, 400, origin)
  }
  if (typeof password !== 'string' || password.length < 1 || password.length > 1024) {
    return response({ error: 'invalid_request' }, 400, origin)
  }

  const userClient = createClient(url, publishableKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    global: { headers: { Authorization: 'Bearer ' + token } },
  })
  const { data: { user }, error: userError } = await userClient.auth.getUser(token)
  if (userError || !user?.email) return response({ error: 'not_authenticated' }, 401, origin)

  const reauthClient = createClient(url, publishableKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  })
  const { data: reauth, error: reauthError } = await reauthClient.auth.signInWithPassword({
    email: user.email,
    password,
  })
  if (reauthError || reauth.user?.id !== user.id) {
    return response({ error: 'password_reauthentication_failed' }, 403, origin)
  }

  const admin = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  })
  const { error: deleteError } = await admin.auth.admin.deleteUser(user.id)
  if (deleteError) return response({ error: 'account_deletion_failed' }, 500, origin)
  return response({ deleted: true }, 200, origin)
})
