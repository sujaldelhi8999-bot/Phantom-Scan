import { createClient, type SupabaseClient, type Provider } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabase: SupabaseClient | null =
  supabaseUrl && supabaseAnonKey ? createClient(supabaseUrl, supabaseAnonKey) : null;

export const supabaseConfigured = supabase !== null;

export async function signInWithProvider(provider: Provider): Promise<void> {
  if (!supabase) {
    throw new Error('Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.');
  }
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider,
    options: {
      redirectTo: `${window.location.origin}/auth/callback`,
    },
  });
  if (error) throw new Error(error.message);
  if (!data.url) throw new Error('Could not start the provider login. Please try again.');
  window.location.href = data.url;
}

export async function exchangeSupabaseSession(): Promise<string | null> {
  if (!supabase) return null;
  const { data: existing, error: sessionError } = await supabase.auth.getSession();
  if (sessionError) throw sessionError;
  if (existing.session?.access_token) return existing.session.access_token;

  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) throw error;
    window.history.replaceState({}, document.title, window.location.pathname);
    const { data, error: afterError } = await supabase.auth.getSession();
    if (afterError) throw afterError;
    return data.session?.access_token ?? null;
  }
  return null;
}

export async function signOutOfSupabase(): Promise<void> {
  if (!supabase) return;
  await supabase.auth.signOut();
}
