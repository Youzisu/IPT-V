// cloudflare-worker-auth.js
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event))
})

async function handleRequest(event) {
  const request = event.request
  const url = new URL(request.url)

  // 从环境变量获取凭证
  const AUTH_USER = event.env.AUTH_USER
  const AUTH_PASS = event.env.AUTH_PASS

  // 屏蔽爬虫配置
  const BLOCKED_UA = [
    /googlebot/i, /bingbot/i, /baiduspider/i,
    /facebookexternalhit/i, /twitterbot/i,
    /ahrefsbot/i, /semrushbot/i
  ]

  // 第一步：屏蔽爬虫
  const ua = request.headers.get('User-Agent') || ''
  if (BLOCKED_UA.some(pattern => pattern.test(ua))) {
    return blockResponse('机器人访问被拒绝')
  }

  // 第二步：检查认证状态
  const cookie = getCookie(request, 'libretv_auth')
  if (cookie === 'verified') {
    return fetchAndModifyResponse(request)
  }

  // 第三步：处理 Basic Auth
  const authHeader = request.headers.get('Authorization')
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const [username, password] = decodeBasicAuth(authHeader)
      if (username === AUTH_USER && password === AUTH_PASS) {
        const response = await fetch(request)
        return setAuthCookie(response)
      }
    } catch (error) {
      return authChallenge('认证信息格式错误')
    }
  }

  // 第四步：返回认证要求
  return authChallenge('需要认证访问')
}

// 工具函数 -------------------------------------------------
function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || ''
  const match = cookieHeader.match(new RegExp(`${name}=([^;]+)`))
  return match ? match[1] : null
}

function decodeBasicAuth(header) {
  const base64 = header.split(' ')[1]
  const text = atob(base64)
  return text.split(':')
}

function blockResponse(message) {
  return new Response(message, {
    status: 403,
    headers: { 'Cache-Control': 'no-store' }
  })
}

function authChallenge(message = '需要认证') {
  return new Response(message, {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="LibreTV 安全访问"',
      'Cache-Control': 'no-store'
    }
  })
}

async function fetchAndModifyResponse(request) {
  const response = await fetch(request)
  
  // 修改响应头增强安全性
  const newHeaders = new Headers(response.headers)
  newHeaders.set('X-Content-Type-Options', 'nosniff')
  newHeaders.set('X-Frame-Options', 'DENY')
  
  return new Response(response.body, {
    status: response.status,
    headers: newHeaders
  })
}

function setAuthCookie(response) {
  const cookie = [
    'libretv_auth=verified',
    'Path=/',
    'Max-Age=21600',    // 6小时有效期
    'Secure',
    'HttpOnly',
    'SameSite=Lax'
  ].join('; ')

  const newHeaders = new Headers(response.headers)
  newHeaders.set('Set-Cookie', cookie)
  
  return new Response(response.body, {
    status: response.status,
    headers: newHeaders
  })
}
