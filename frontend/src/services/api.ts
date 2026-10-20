import axios from 'axios';

/**
 * Auth lifecycle events. The interceptor must NEVER navigate on its own: a hard
 * window.location.href = '/login' combined with the router guard produced an
 * endless reload (401 -> assign('/login') -> guard sends '/' -> 401 -> ...).
 * The session is cleared here and the router performs ONE redirect instead.
 */
export const AUTH_UNAUTHORIZED_EVENT = 'dns-panel:unauthorized';
export function onUnauthorized(handler: () => void): () => void {
  window.addEventListener(AUTH_UNAUTHORIZED_EVENT, handler);
  return () => window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, handler);
}

const base = String(import.meta.env.BASE_URL || '/');
const apiBase = base.endsWith('/') ? `${base}api` : `${base}/api`;

/**
 * Axios 实例配置
 */
const api = axios.create({
  baseURL: apiBase,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * 请求拦截器 - 添加 Token
 */
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

/**
 * 响应拦截器 - 统一错误处理
 */
api.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    if (error.response) {
      const { status, data } = error.response;

      // 401 未授权 - 只清理会话并广播事件，由路由统一跳转一次。
      //（这里以前直接 window.location.href = '/login'，与路由守卫互相弹跳，
      //  形成 401 -> /login -> '/' -> 401 ... 的无限刷新。）
      if (status === 401) {
        const message = String(data?.message || '');
        const authMessages = ['未提供认证令牌', '无效或过期的令牌', '认证失败'];
        const shouldLogout = authMessages.some(m => message.includes(m));

        if (shouldLogout) {
          const hadToken = Boolean(localStorage.getItem('token'));
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          // 只有在确实存在会话时才广播，避免登录页自身的 401 反复触发跳转。
          if (hadToken) {
            window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
          }
        }
      }

      // 返回错误信息
      return Promise.reject(`${status}: ${data?.message || '请求失败'}`);
    }

    // 网络错误
    if (error.request) {
      return Promise.reject('网络连接失败，请检查网络');
    }

    return Promise.reject(error.message || '未知错误');
  }
);

export default api;
