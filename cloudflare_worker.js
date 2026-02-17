/**
 * Cloudflare Worker — WebSocket tunnel front
 *
 * Setup:
 *   1. Create a Worker in CF Dashboard
 *   2. Set Environment Variable: ORIGIN_HOST = "YOUR_VPS_IP:443"
 *   3. Add a route: *.yourdomain.com/api/v1/stream  → this worker
 *   4. Enable "WebSockets" in CF Dashboard → Network settings
 *
 * How it works:
 *   Client  →  wss://cf-worker.yourdomain.com/api/v1/stream
 *   Worker  →  wss://YOUR_VPS_IP:443/api/v1/stream
 *
 * The client's TLS terminates at Cloudflare edge PoP.
 * CF connects to your origin via its own infrastructure.
 * The visible IP is Cloudflare's — not your datacenter's.
 */

const WS_PATH = "/api/v1/stream";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        // Only proxy the tunnel path
        if (url.pathname !== WS_PATH) {
            // Return convincing 404 for any other path
            return new Response(
                `<!DOCTYPE html><html><head><title>404 Not Found</title></head>` +
                `<body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>`,
                {
                    status: 404,
                    headers: {
                        "Content-Type": "text/html",
                        "Server": "nginx/1.24.0",
                        "Cache-Control": "no-cache",
                    },
                }
            );
        }

        // Verify it's a WebSocket upgrade
        const upgradeHeader = request.headers.get("Upgrade");
        if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
            return new Response("Expected WebSocket", { status: 426 });
        }

        // Build origin URL
        const originHost = env.ORIGIN_HOST; // e.g. "1.2.3.4:443"
        const originUrl = `wss://${originHost}${WS_PATH}`;

        // Forward all headers (including our x-auth, x-nonce)
        const headers = new Headers(request.headers);
        headers.set("Host", originHost.split(":")[0]);

        // CF WebSocket proxy
        return fetch(originUrl, {
            method: request.method,
            headers,
            body: request.body,
        });
    },
};
