"""Bound configuration request bodies before JSON parsing."""

from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    def __init__(self, app, limit: int = 1024 * 1024):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] not in ("POST", "PUT", "PATCH")
            or not scope["path"].startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            await JSONResponse({"detail": "Invalid content length"}, status_code=400)(
                scope, receive, send
            )
            return
        if declared < 0 or declared > self.limit:
            await JSONResponse({"detail": "Request body exceeds limit"}, status_code=413)(
                scope, receive, send
            )
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                await JSONResponse({"detail": "Request body exceeds limit"}, status_code=413)(
                    scope, receive, send
                )
                return
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
