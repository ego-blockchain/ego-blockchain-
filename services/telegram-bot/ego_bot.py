import html
import json
import os
import sys
import time
import urllib.parse
import urllib.request

SITE = "https://egoblockchain.com"
RPC = "https://rpc.egoblockchain.com"
ALLOWED_HOSTS = ("egoblockchain.com",)
ALLOWED_PREFIXES = ("https://github.com/ego-blockchain",)
STRIKES_TO_MUTE = 3
STRIKE_WINDOW_SECS = 24 * 3600
MUTE_SECS = 24 * 3600
NOTICE_SECS = 30
ADMIN_CACHE_SECS = 600
STATS_CACHE_SECS = 30
COMMAND_COOLDOWN_SECS = 10
POLL_SECS = 10

RULES = (
    "<b>Group rules</b>\n"
    "1. No advertising, promotions or links to other projects.\n"
    "2. No scams, spam or harmful messages.\n"
    "3. Never ask for or share private keys or recovery phrases.\n"
    "4. Be respectful.\n\n"
    "Messages that break these rules are deleted, and repeat offenders are muted."
)

WELCOME = (
    "Welcome to Ego, {names}! 👋\n\n"
    "Ego is a quantum-safe blockchain you can run from your own computer with Ego Desktop.\n\n"
    "To keep this group safe and useful for everyone:\n"
    "🚫 No advertising, promotions or links to other projects\n"
    "🚫 No scams, spam or harmful messages\n"
    "🚫 No asking for or sharing private keys or recovery phrases\n\n"
    "⚠️ Our team will never DM you first or ask for your recovery phrase. Anyone who does is a scammer.\n\n"
    "📥 Download: " + SITE + "/download\n"
    "📖 Docs: " + SITE + "/docs\n\n"
    "Type /help to see what I can tell you."
)

HELP = (
    "<b>What I can do</b>\n"
    "/version: the latest Ego Desktop version\n"
    "/stats: block height, nodes online and price\n"
    "/download: where to get Ego Desktop\n"
    "/rules: the group rules"
)

COMMANDS = [
    {"command": "version", "description": "Latest Ego Desktop version"},
    {"command": "stats", "description": "Block height, nodes online and price"},
    {"command": "download", "description": "Where to get Ego Desktop"},
    {"command": "rules", "description": "Group rules"},
    {"command": "help", "description": "What this bot can do"},
]


def entity_text(text, entity):
    raw = text.encode("utf-16-le")
    start = entity.get("offset", 0) * 2
    end = start + entity.get("length", 0) * 2
    return raw[start:end].decode("utf-16-le", errors="ignore")


def normalize_url(url):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    return url


def link_allowed(url):
    url = normalize_url(url)
    if any(url.lower().startswith(p.lower()) for p in ALLOWED_PREFIXES):
        return True
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS)


def links_in(message):
    found = []
    for text_key, entities_key in (("text", "entities"), ("caption", "caption_entities")):
        text = message.get(text_key) or ""
        for entity in message.get(entities_key) or []:
            kind = entity.get("type")
            if kind == "url":
                found.append(entity_text(text, entity))
            elif kind == "text_link":
                found.append(entity.get("url", ""))
    for markup_row in (message.get("reply_markup") or {}).get("inline_keyboard") or []:
        for button in markup_row:
            if button.get("url"):
                found.append(button["url"])
    return found


def forwarded_from_channel(message):
    origin = message.get("forward_origin") or {}
    return origin.get("type") == "channel" or "forward_from_chat" in message


def breaks_rules(message):
    if forwarded_from_channel(message):
        return "forwarded posts from other channels"
    if any(not link_allowed(url) for url in links_in(message)):
        return "links"
    return None


def command_of(message):
    text = (message.get("text") or "").strip()
    if not text.startswith("/"):
        return None
    return text.split()[0].split("@")[0][1:].lower()


def display_name(user):
    name = " ".join(p for p in (user.get("first_name"), user.get("last_name")) if p) or user.get("username") or "friend"
    return html.escape(name)


def format_stats(health, nodes, gateways, egoc):
    lines = ["<b>Ego network</b>"]
    if health:
        lines.append("⛓ Block height: {:,}".format(int(health.get("block_height", 0))))
    if nodes is not None:
        lines.append("🖥 Nodes online: {:,}".format(nodes))
    if gateways is not None:
        lines.append("🌐 Public gateways: {:,}".format(gateways))
    if egoc and egoc.get("usd") is not None:
        lines.append("💰 EGOC price: ${:g}".format(float(egoc["usd"])))
    if len(lines) == 1:
        lines.append("The network data is not available right now. Try again in a minute.")
    return "\n".join(lines)


def format_version(manifest):
    if not manifest:
        return "I couldn't reach the website right now. Try again in a minute."
    version = html.escape(str(manifest.get("version", "?")))
    lines = ["<b>Ego Desktop v" + version + "</b>"]
    required = manifest.get("required_version")
    if required and required == manifest.get("version"):
        lines.append("This is a required update for every node.")
    elif required:
        lines.append("Nodes must run at least v" + html.escape(str(required)) + ".")
    notes = manifest.get("notes")
    if notes:
        lines.append("")
        lines.append(html.escape(str(notes)))
    lines.append("")
    lines.append("📥 " + SITE + "/download")
    return "\n".join(lines)


class Bot:
    def __init__(self, token):
        self.api = "https://api.telegram.org/bot" + token + "/"
        self.offset = 0
        self.admins = {}
        self.strikes = {}
        self.last_welcome = {}
        self.cooldowns = {}
        self.pending_deletes = []
        self.cache = {}
        self.me = None

    def call(self, method, **params):
        data = json.dumps(params).encode()
        request = urllib.request.Request(self.api + method, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=POLL_SECS + 20) as response:
                body = json.loads(response.read().decode())
        except Exception as error:
            print("telegram " + method + " failed: " + str(error), file=sys.stderr, flush=True)
            return None
        if not body.get("ok"):
            print("telegram " + method + " refused: " + str(body.get("description")), file=sys.stderr, flush=True)
            return None
        return body.get("result")

    def fetch(self, url):
        now = time.time()
        hit = self.cache.get(url)
        if hit and now - hit[0] < STATS_CACHE_SECS:
            return hit[1]
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "ego-telegram-bot"})
            with urllib.request.urlopen(request, timeout=10) as response:
                value = json.loads(response.read().decode())
        except Exception as error:
            print("fetch " + url + " failed: " + str(error), file=sys.stderr, flush=True)
            value = None
        self.cache[url] = (now, value)
        return value

    def is_admin(self, chat_id, user_id):
        now = time.time()
        cached = self.admins.get(chat_id)
        if not cached or now - cached[0] > ADMIN_CACHE_SECS:
            result = self.call("getChatAdministrators", chat_id=chat_id)
            ids = {m["user"]["id"] for m in result or []}
            cached = (now, ids)
            self.admins[chat_id] = cached
        return user_id in cached[1]

    def send(self, chat_id, text, thread_id=None, delete_after=None):
        params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "link_preview_options": {"is_disabled": True}}
        if thread_id:
            params["message_thread_id"] = thread_id
        sent = self.call("sendMessage", **params)
        if sent and delete_after:
            self.pending_deletes.append((time.time() + delete_after, chat_id, sent["message_id"]))
        return sent

    def delete(self, chat_id, message_id):
        self.call("deleteMessage", chat_id=chat_id, message_id=message_id)

    def run_pending_deletes(self):
        now = time.time()
        due = [d for d in self.pending_deletes if d[0] <= now]
        self.pending_deletes = [d for d in self.pending_deletes if d[0] > now]
        for _, chat_id, message_id in due:
            self.delete(chat_id, message_id)

    def welcome(self, message):
        chat_id = message["chat"]["id"]
        people = [u for u in message.get("new_chat_members") or [] if not u.get("is_bot")]
        self.delete(chat_id, message["message_id"])
        if not people:
            return
        names = ", ".join(display_name(u) for u in people[:5])
        previous = self.last_welcome.get(chat_id)
        if previous:
            self.delete(chat_id, previous)
        sent = self.send(chat_id, WELCOME.format(names=names), message.get("message_thread_id"))
        if sent:
            self.last_welcome[chat_id] = sent["message_id"]

    def strike(self, message, reason):
        chat_id = message["chat"]["id"]
        user = message["from"]
        thread_id = message.get("message_thread_id")
        self.delete(chat_id, message["message_id"])
        now = time.time()
        key = (chat_id, user["id"])
        times = [t for t in self.strikes.get(key, []) if now - t < STRIKE_WINDOW_SECS]
        times.append(now)
        self.strikes[key] = times
        name = display_name(user)
        if len(times) >= STRIKES_TO_MUTE:
            self.call(
                "restrictChatMember",
                chat_id=chat_id,
                user_id=user["id"],
                permissions={"can_send_messages": False},
                until_date=int(now + MUTE_SECS),
            )
            self.strikes.pop(key, None)
            self.send(chat_id, name + " was muted for 24 hours for posting " + reason + " again.", thread_id, NOTICE_SECS)
        else:
            left = STRIKES_TO_MUTE - len(times)
            self.send(
                chat_id,
                name + ", " + reason + " are not allowed here, so I removed your message. "
                + str(left) + " more and you will be muted for 24 hours.",
                thread_id,
                NOTICE_SECS,
            )

    def answer(self, message, command):
        chat_id = message["chat"]["id"]
        thread_id = message.get("message_thread_id")
        now = time.time()
        key = (chat_id, command)
        if now - self.cooldowns.get(key, 0) < COMMAND_COOLDOWN_SECS:
            return
        self.cooldowns[key] = now
        if command in ("start", "help"):
            text = HELP
        elif command == "rules":
            text = RULES
        elif command == "download":
            text = "📥 Ego Desktop for Windows, macOS and Linux:\n" + SITE + "/download"
        elif command == "version":
            text = format_version(self.fetch(SITE + "/version.json"))
        elif command == "stats":
            health = self.fetch(RPC + "/health")
            nodes = self.fetch(RPC + "/nodes")
            gateways = self.fetch(RPC + "/gateways")
            egoc = self.fetch(RPC + "/egoc")
            text = format_stats(
                health,
                len(nodes.get("nodes", [])) if isinstance(nodes, dict) else None,
                len(gateways.get("gateways", [])) if isinstance(gateways, dict) else None,
                egoc,
            )
        else:
            return
        self.send(chat_id, text, thread_id)

    def handle(self, message):
        chat = message.get("chat") or {}
        if message.get("new_chat_members"):
            self.welcome(message)
            return
        if message.get("left_chat_member"):
            self.delete(chat["id"], message["message_id"])
            return
        user = message.get("from") or {}
        if not user or user.get("is_bot"):
            return
        group = chat.get("type") in ("group", "supergroup")
        if group and not message.get("sender_chat") and not self.is_admin(chat["id"], user["id"]):
            reason = breaks_rules(message)
            if reason:
                self.strike(message, reason)
                return
        command = command_of(message)
        if command:
            self.answer(message, command)

    def run(self):
        self.me = self.call("getMe")
        if not self.me:
            print("the bot token was refused; check TELEGRAM_BOT_TOKEN", file=sys.stderr, flush=True)
            sys.exit(1)
        self.call("setMyCommands", commands=COMMANDS)
        print("running as @" + str(self.me.get("username")), flush=True)
        while True:
            updates = self.call(
                "getUpdates",
                offset=self.offset,
                timeout=POLL_SECS,
                allowed_updates=["message", "edited_message"],
            )
            if updates is None:
                time.sleep(5)
            for update in updates or []:
                self.offset = update["update_id"] + 1
                message = update.get("message") or update.get("edited_message")
                if message:
                    try:
                        self.handle(message)
                    except Exception as error:
                        print("update failed: " + str(error), file=sys.stderr, flush=True)
            self.run_pending_deletes()


if __name__ == "__main__":
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        print("set TELEGRAM_BOT_TOKEN to the token from @BotFather", file=sys.stderr)
        sys.exit(1)
    Bot(token).run()
