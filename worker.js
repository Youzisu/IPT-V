// cloudflare-worker.js
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event))
})

async function handleRequest(event) {
  const request = event.request
  const url = new URL(request.url)

  // 从环境变量获取凭证
  const USERNAME = event.env.AUTH_USER
  const PASSWORD = event.env.AUTH_PASS

  // 爬虫屏蔽列表
  const BLOCKED_UA = [
    /googlebot/i, /bingbot/i, /baiduspider/i,
    /facebookexternalhit/i, /twitterbot/i
  ]

  // 第一步：屏蔽爬虫
  const ua = request.headers.get('User-Agent') || ''
  if (BLOCKED_UA.some(pattern => pattern.test(ua))) {
    return new Response('Access Denied', { status: 403 })
  }

  // 第二步：认证检查
  const cookie = request.headers.get('Cookie') || ''
  const hasValidCookie = cookie.includes('auth_verified=1')

  // 已认证直接放行
  if (hasValidCookie) {
    return fetch(request)
  }

  // 第三步：Basic Auth 验证
  const authHeader = request.headers.get('Authorization')
  if (authHeader && authHeader.startsWith('Basic ')) {
    const base64Credentials = authHeader.split(' ')[1]
    const credentials = atob(base64Credentials)
    const [username, password] = credentials.split(':')

    if (username === USERNAME && password === PASSWORD) {
      // 认证通过，设置Cookie并转发请求
      const response = await fetch(request)
      return new Response(response.body, {
        status: response.status,
        headers: {
          ...response.headers,
          'Set-Cookie': 'auth_verified=1; Path=/; Max-Age=21600; Secure; HttpOnly'
        }
      })
    }
  }

  // 第四步：返回认证要求
  return new Response('Authentication Required', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Secure Area"',
      'Cache-Control': 'no-store'
    }
  })
}
