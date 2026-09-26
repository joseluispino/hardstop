#!/usr/bin/env python3
"""
harvest_launch_telemetry.py
Harvests deployed launch posts from X and Bluesky, saves them to SQLite and JSON,
analyzes reach and uniqueness, and updates HARD_STOP_LAUNCH_STRATEGY.md with exact copy.
"""

import os
import re
import json
import sqlite3
import urllib.request
import html
import time
from datetime import datetime, timezone

STRATEGY_FILE = "/home/jpino/Obsidian/Axiom/_Meta/Launch/HARD_STOP_LAUNCH_STRATEGY.md"
SQLITE_DB = "/home/jpino/src/hardstop/launch_telemetry.sqlite"
JSON_FILE = "/home/jpino/src/hardstop/launch_telemetry.json"

def fetch_x_text(url):
    oembed_url = f"https://publish.x.com/oembed?url={url}"
    req = urllib.request.Request(oembed_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            m = re.search(r'<p[^>]*>(.*?)</p>', data["html"], re.DOTALL)
            if m:
                t = m.group(1)
                t = re.sub(r'<br\s*/?>', '\n', t)
                t = re.sub(r'<a[^>]*>(.*?)</a>', r'\1', t)
                return html.unescape(t).strip()
    except Exception as e:
        return f"Error fetching {url}: {e}"

def fetch_bsky_text(url):
    try:
        rkey = url.rstrip("/").split("/")[-1]
        req = urllib.request.Request(
            f"https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=at://did:plc:nr66rfrucbm2x2ywmftuzzsf/app.bsky.feed.post/{rkey}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["thread"]["post"]["record"]["text"].strip()
    except Exception as e:
        return f"Error fetching {url}: {e}"

def parse_followers(text):
    m = re.search(r'([\d.]+)\s*M\s*followers', text, re.I)
    if m:
        return int(float(m.group(1)) * 1_000_000)
    k = re.search(r'([\d.]+)\s*K\s*followers', text, re.I)
    if k:
        return int(float(k.group(1)) * 1_000)
    return 0

def parse_views(text):
    m = re.search(r'([\d.]+)\s*M\s*views', text, re.I)
    if m:
        return int(float(m.group(1)) * 1_000_000)
    k = re.search(r'([\d.]+)\s*K\s*views', text, re.I)
    if k:
        return int(float(k.group(1)) * 1_000)
    return 0

def main():
    with open(STRATEGY_FILE, "r") as f:
        content = f.read()

    pattern = r'\* \*\*Breaking Trigger (\d+)\s*\((.*?)\)\*\*:\s*(.*?)(?=\n\* \*\*Breaking Trigger|\n###|\Z)'
    matches = re.findall(pattern, content, re.DOTALL)
    print(f"Parsed {len(matches)} Breaking Triggers.")

    records = []
    
    for num_str, title, body in matches:
        num = int(num_str)
        followers = parse_followers(body)
        views = parse_views(body)
        
        # Target post URL
        target_post_match = re.search(r'\[(?:[^\]]+)\]\((https?://[^\s)]+)\)', body)
        target_post_url = target_post_match.group(1) if target_post_match else ""
        
        # Action summary
        action_match = re.search(r'\*\s*\*\*Action\*\*:\s*(.*?)(?=\n\s*\*|\Z)', body, re.DOTALL)
        action_text = action_match.group(1).strip() if action_match else ""
        
        # My deployed URLs
        my_urls = list(dict.fromkeys(re.findall(r'https?://(?:x\.com|bsky\.app)(?:/profile)?/joseluispino[^\s)\]]+', body)))
        
        for my_url in my_urls:
            if "x.com" in my_url:
                post_text = fetch_x_text(my_url)
                platform = "x"
            else:
                post_text = fetch_bsky_text(my_url)
                platform = "bluesky"
            
            status_id = my_url.rstrip("/").split("/")[-1]
            
            record = {
                "trigger_num": num,
                "title": title.strip(),
                "platform": platform,
                "status_id": status_id,
                "my_url": my_url,
                "target_post_url": target_post_url,
                "target_followers": followers,
                "target_views": views,
                "action_summary": action_text,
                "deployed_copy": post_text,
                "char_count": len(post_text),
                "harvested_at": datetime.now(timezone.utc).isoformat()
            }
            records.append(record)
            print(f"Trigger {num:02d} [{platform.upper()}]: {len(post_text)} chars | {post_text[:60]}...")
            time.sleep(0.05)

    # Save to JSON
    with open(JSON_FILE, "w") as f:
        json.dump(records, f, indent=2)
    print(f"Saved {len(records)} records to {JSON_FILE}")

    # Save to SQLite
    conn = sqlite3.connect(SQLITE_DB)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS launch_telemetry")
    cur.execute("""
        CREATE TABLE launch_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trigger_num INTEGER,
            title TEXT,
            platform TEXT,
            status_id TEXT UNIQUE,
            my_url TEXT,
            target_post_url TEXT,
            target_followers INTEGER,
            target_views INTEGER,
            action_summary TEXT,
            deployed_copy TEXT,
            char_count INTEGER,
            harvested_at TEXT
        )
    """)
    for r in records:
        cur.execute("""
            INSERT INTO launch_telemetry (
                trigger_num, title, platform, status_id, my_url,
                target_post_url, target_followers, target_views,
                action_summary, deployed_copy, char_count, harvested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r["trigger_num"], r["title"], r["platform"], r["status_id"], r["my_url"],
            r["target_post_url"], r["target_followers"], r["target_views"],
            r["action_summary"], r["deployed_copy"], r["char_count"], r["harvested_at"]
        ))
    conn.commit()
    conn.close()
    print(f"Saved {len(records)} records to {SQLITE_DB}")

    # Uniqueness Analysis
    all_texts = [r["deployed_copy"] for r in records]
    vocab = set()
    for t in all_texts:
        tokens = re.findall(r'[a-zA-Z0-9_\-\.\:\@]+', t.lower())
        vocab.update(tokens)
    print(f"Total Unique Vocabulary across all posts: {len(vocab)} words.")

if __name__ == "__main__":
    main()
