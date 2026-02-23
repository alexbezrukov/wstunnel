const WS_PATH = "/api/v1/stream";
const ORIGIN = "tunnel.nevergonnagiveyouup.tech";

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (url.pathname !== WS_PATH) {
            return new Response("404 Not Found", { status: 404 });
        }

        const upgradeHeader = request.headers.get("Upgrade");
        if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
            return new Response("Expected WebSocket", { status: 426 });
        }

        // Создаём WebSocket пару: client <-> worker
        const [client, worker] = Object.values(new WebSocketPair());

        // Подключаемся к origin, пробрасывая все заголовки тоннеля
        const originHeaders = new Headers();
        originHeaders.set("x-auth", request.headers.get("x-auth") || "");
        originHeaders.set("x-nonce", request.headers.get("x-nonce") || "");
        originHeaders.set("x-target", request.headers.get("x-target") || "");

        const originResp = await fetch(`https://${ORIGIN}${WS_PATH}`, {
            headers: originHeaders,
            cf: { websocket: true },
        });

        if (originResp.status !== 101) {
            return new Response("Origin WebSocket failed", { status: 502 });
        }

        const origin = originResp.webSocket;
        origin.accept();
        client.accept();

        // Проброс сообщений в обе стороны
        client.addEventListener("message", (evt) => {
            try { origin.send(evt.data); } catch (e) { }
        });
        origin.addEventListener("message", (evt) => {
            try { client.send(evt.data); } catch (e) { }
        });
        client.addEventListener("close", (evt) => {
            try { origin.close(evt.code, evt.reason); } catch (e) { }
        });
        origin.addEventListener("close", (evt) => {
            try { client.close(evt.code, evt.reason); } catch (e) { }
        });
        client.addEventListener("error", () => { try { origin.close(); } catch (e) { } });
        origin.addEventListener("error", () => { try { client.close(); } catch (e) { } });

        return new Response(null, { status: 101, webSocket: client });
    },
};