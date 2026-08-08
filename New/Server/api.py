"""HTTP API exposed by the VPN Server process (the only DB owner).

This Flask app is created with a live ``VPNServer`` instance and serves both:

  * the Admin API  (JWT admin token; users / firewall / logs)
  * the Portal API  (JWT user token; register / login / status / quota)

Every data operation is delegated to ``VPNServer`` methods, which are the only
code allowed to touch SQLite. Neither the Admin Panel nor the Client Portal
frontends import ``Database`` or open ``vpn.db`` — they are pure HTTP clients of
this API (or of a co-located instance of it).

Create the app with :func:`create_api_app(server)` and run it on the desired
port, or mount the packaged frontends via ``admin_panel``/``client_portal``.
"""

import os
from typing import Optional

from flask import Flask, request, jsonify, make_response, g

from web import issue_token, jwt_required, human_bytes

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"


def create_api_app(server, name: str = "vpn_api") -> Flask:
    """Build a Flask app bound to a live VPNServer (the sole DB owner)."""
    app = Flask(name)
    app.config["SERVER"] = server

    def srv():
        return app.config["SERVER"]

    # ------------------------------------------------------------------ #
    # Auth (both roles)
    # ------------------------------------------------------------------ #
    @app.post("/api/admin/login")
    def admin_login():
        data = request.get_json(silent=True) or {}
        if (data.get("username") != ADMIN_USERNAME
                or data.get("password") != ADMIN_PASSWORD):
            return jsonify({"error": "Invalid admin credentials"}), 401
        token = issue_token(ADMIN_USERNAME, is_admin=True,
                            remember=bool(data.get("remember")))
        resp = make_response(jsonify({"ok": True, "token": token}))
        resp.set_cookie("token", token, httponly=True, samesite="Lax")
        return resp

    @app.post("/api/portal/register")
    def portal_register():
        data = request.get_json(silent=True) or {}
        result = srv().portal_register(data.get("username", ""), data.get("password", ""))
        if not result.get("ok"):
            code = 409 if "exists" in (result.get("error") or "") else 400
            return jsonify({"error": result.get("error")}), code
        return jsonify({"ok": True})

    @app.post("/api/portal/login")
    def portal_login():
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        result = srv().portal_authenticate(username, data.get("password", ""))
        if not result.get("ok"):
            err = result.get("error") or "Login failed"
            code = 403 if err in ("Account banned", "This account cannot use the portal") else 401
            return jsonify({"error": err}), code
        token = issue_token(username, is_admin=False, remember=bool(data.get("remember")))
        resp = make_response(jsonify({"ok": True, "token": token}))
        resp.set_cookie("token", token, httponly=True, samesite="Lax")
        return resp

    @app.post("/api/logout")
    def logout():
        resp = make_response(jsonify({"ok": True}))
        resp.delete_cookie("token")
        return resp

    # ------------------------------------------------------------------ #
    # Portal (user token)
    # ------------------------------------------------------------------ #
    @app.get("/api/portal/status")
    @jwt_required(admin_only=False)
    def portal_status():
        info = srv().portal_status(g.username)
        if info is None:
            return jsonify({"error": "User not found"}), 404
        info["remaining_quota_h"] = human_bytes(info.get("remaining_quota"))
        return jsonify(info)

    @app.post("/api/portal/quota")
    @jwt_required(admin_only=False)
    def portal_quota():
        data = request.get_json(silent=True) or {}
        result = srv().portal_request_quota(g.username, data.get("amount", 0))
        if not result.get("ok"):
            code = 404 if result.get("error") == "User not found" else 400
            return jsonify({"error": result.get("error")}), code
        result["remaining_quota_h"] = human_bytes(result.get("remaining_quota"))
        return jsonify(result)

    # ------------------------------------------------------------------ #
    # Admin (admin token)
    # ------------------------------------------------------------------ #
    @app.get("/api/admin/users")
    @jwt_required(admin_only=True)
    def admin_users():
        users = srv().list_users()
        for u in users:
            u.pop("password", None)
            u["remaining_quota_h"] = human_bytes(u.get("remaining_quota"))
        return jsonify({"users": users})

    @app.post("/api/admin/users/<username>/ban")
    @jwt_required(admin_only=True)
    def admin_ban(username):
        ok = srv().ban_user(username)  # bans in DB and kicks live sessions
        return jsonify({"ok": ok})

    @app.post("/api/admin/users/<username>/unban")
    @jwt_required(admin_only=True)
    def admin_unban(username):
        return jsonify({"ok": srv().unban_user(username)})

    @app.post("/api/admin/users/<username>/quota")
    @jwt_required(admin_only=True)
    def admin_quota(username):
        data = request.get_json(silent=True) or {}
        try:
            amount = int(data.get("amount", 0))
        except (TypeError, ValueError):
            return jsonify({"error": "amount must be an integer"}), 400
        if amount == 0:
            return jsonify({"error": "amount must be non-zero"}), 400
        new_total = srv().add_quota(username, amount)
        if new_total < 0:
            return jsonify({"error": "user not found"}), 404
        return jsonify({"ok": True, "remaining_quota": new_total,
                        "remaining_quota_h": human_bytes(new_total)})

    @app.get("/api/admin/firewall")
    @jwt_required(admin_only=True)
    def admin_firewall():
        return jsonify(srv().list_firewall_rules())

    @app.post("/api/admin/firewall/domain")
    @jwt_required(admin_only=True)
    def admin_add_domain():
        data = request.get_json(silent=True) or {}
        try:
            rid = srv().add_firewall_domain(data.get("username", ""), data.get("domain", ""))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True, "id": rid})

    @app.post("/api/admin/firewall/ip")
    @jwt_required(admin_only=True)
    def admin_add_ip():
        data = request.get_json(silent=True) or {}
        try:
            rid = srv().add_firewall_ip(data.get("username", ""), data.get("ip", ""))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True, "id": rid})

    @app.delete("/api/admin/firewall/<rule_type>/<int:rule_id>")
    @jwt_required(admin_only=True)
    def admin_del_rule(rule_type, rule_id):
        try:
            ok = srv().remove_firewall_rule(rule_id, rule_type)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": ok})

    @app.get("/api/admin/logs")
    @jwt_required(admin_only=True)
    def admin_logs():
        username = request.args.get("username") or None
        try:
            limit = int(request.args.get("limit", 500))
        except ValueError:
            limit = 500
        return jsonify({"logs": srv().get_traffic_logs(username, limit)})

    @app.post("/api/admin/logs/clear")
    @jwt_required(admin_only=True)
    def admin_clear_logs():
        srv().clear_traffic_logs()
        return jsonify({"ok": True})

    return app
