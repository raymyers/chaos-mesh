const { createProxyMiddleware } = require('http-proxy-middleware')

const API_URL = process.env.REACT_APP_API_URL

module.exports = function (app) {
  app.use(
    '/api',
    createProxyMiddleware({
      followRedirects: false,
      secure: false,
      target: API_URL,
      onProxyRes: function (proxyRes, req, res) {
        proxyRes.headers['Access-Control-Allow-Origin'] = '*'
      },
      changeOrigin: true,
    })
  )
}
