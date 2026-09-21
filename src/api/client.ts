const API_BASE = '/api';

export function getAuthToken(): string | null {
  return localStorage.getItem('cybershield_token');
}

export function setAuthToken(token: string) {
  localStorage.setItem('cybershield_token', token);
}

export function clearAuthToken() {
  localStorage.removeItem('cybershield_token');
}

export async function apiFetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  const contentType = response.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');

  if (!response.ok) {
    let errMsg = `Request failed (${response.status}): ${response.statusText}`;
    if (isJson) {
      try {
        const errJson = await response.json();
        if (errJson.detail) errMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
        else if (errJson.message) errMsg = errJson.message;
        else if (errJson.error) errMsg = errJson.error;
      } catch {
        // fallback
      }
    } else {
      const text = await response.text();
      if (text && text.length < 200) {
        errMsg = text;
      }
    }
    throw new Error(errMsg);
  }

  if (!isJson) {
    throw new Error(`Invalid response format from server: expected JSON but received ${contentType || 'HTML'}`);
  }

  return response.json();
}
