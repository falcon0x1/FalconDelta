#!/usr/bin/env python3
"""
𓅃 FalconDelta - APK Security Analyzer & Comparator
By: falcon0x1 𓅃

A powerful tool to analyze and compare Android APK files
with deep DEX analysis and risk assessment.

https://github.com/falcon0x1/FalconDelta
"""

import click
import json
import os
import re
from datetime import datetime
from androguard.core.apk import APK
from androguard.core.dex import DEX


# ============================================================
# DANGEROUS PERMISSIONS - HIGH RISK
# ============================================================
DANGEROUS_PERMISSIONS = {
    # Privacy & Data Access
    "android.permission.READ_SMS": "𓅂 قراءة الرسائل النصية",
    "android.permission.SEND_SMS": "𓅂 إرسال رسائل نصية",
    "android.permission.RECEIVE_SMS": "𓅂 استقبال الرسائل",
    "android.permission.READ_CONTACTS": "𓅈 قراءة جهات الاتصال",
    "android.permission.WRITE_CONTACTS": "𓅈 تعديل جهات الاتصال",
    "android.permission.READ_CALL_LOG": "𓅉 قراءة سجل المكالمات",
    "android.permission.WRITE_CALL_LOG": "𓅉 تعديل سجل المكالمات",
    "android.permission.CALL_PHONE": "𓅉 إجراء مكالمات",
    "android.permission.READ_PHONE_STATE": "𓅂 قراءة حالة الهاتف",
    "android.permission.READ_PHONE_NUMBERS": "𓅂 قراءة أرقام الهاتف",
    "android.permission.PROCESS_OUTGOING_CALLS": "𓅉 التحكم بالمكالمات الصادرة",
    
    # Location
    "android.permission.ACCESS_FINE_LOCATION": "𖤍 الموقع الدقيق (GPS)",
    "android.permission.ACCESS_COARSE_LOCATION": "𖤍 الموقع التقريبي",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "𖤍 الموقع في الخلفية",
    
    # Camera & Microphone
    "android.permission.CAMERA": "𓅆 الكاميرا",
    "android.permission.RECORD_AUDIO": "𓅇 تسجيل الصوت",
    
    # Storage & Files
    "android.permission.READ_EXTERNAL_STORAGE": "𓆲 قراءة التخزين",
    "android.permission.WRITE_EXTERNAL_STORAGE": "𓆲 الكتابة على التخزين",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "𓆲 إدارة كل الملفات",
    
    # System & Admin
    "android.permission.REQUEST_INSTALL_PACKAGES": "⬢ تثبيت التطبيقات",
    "android.permission.DELETE_PACKAGES": "⬢ حذف التطبيقات",
    "android.permission.SYSTEM_ALERT_WINDOW": "⬢ النوافذ العائمة",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "⬢ خدمات إمكانية الوصول",
    "android.permission.BIND_DEVICE_ADMIN": "𓆲 مدير الجهاز",
    "android.permission.READ_LOGS": "𓆲 قراءة السجلات",
    
    # Network & Communication
    "android.permission.CHANGE_NETWORK_STATE": "⌘ تغيير حالة الشبكة",
    "android.permission.CHANGE_WIFI_STATE": "⌘ تغيير حالة WiFi",
    
    # Calendar
    "android.permission.READ_CALENDAR": "𓅓 قراءة التقويم",
    "android.permission.WRITE_CALENDAR": "𓅓 تعديل التقويم",
    
    # Body Sensors
    "android.permission.BODY_SENSORS": "𖤍 مستشعرات الجسم",
    "android.permission.ACTIVITY_RECOGNITION": "𖤍 التعرف على النشاط",
}

# URL Patterns for extraction
URL_PATTERNS = [
    r'https?://[^\s\"\'\<\>\)\]\}]+',   # Standard URLs
    r'http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^\s\"\']*',  # IP addresses
    r'[a-zA-Z0-9\-]+\.(?:com|net|org|io|dev|api|xyz|app|cloud)[^\s\"\'\<\>\)\]\}]*',  # Domains
]

# Sensitive URL keywords
SENSITIVE_URL_KEYWORDS = [
    'api', 'admin', 'login', 'auth', 'token', 'key', 'secret', 'password',
    'upload', 'download', 'payment', 'webhook', 'callback', 'debug', 
    'staging', 'dev', 'test', 'internal', 'private', '.env', 'config'
]


def extract_urls_from_dex(apk_path: str) -> dict:
    """
    Extract URLs and strings from DEX files in an APK.
    
    Returns:
        Dictionary with 'urls', 'api_endpoints', 'sensitive_urls'
    """
    apk = APK(apk_path)
    all_urls = set()
    api_endpoints = set()
    sensitive_urls = set()
    
    try:
        # Get all DEX files
        for dex_name in apk.get_dex_names():
            dex_bytes = apk.get_file(dex_name)
            if dex_bytes:
                dex = DEX(dex_bytes)
                
                # Extract strings from DEX
                for string in dex.get_strings():
                    if string:
                        # Check for URLs
                        for pattern in URL_PATTERNS:
                            matches = re.findall(pattern, string, re.IGNORECASE)
                            for match in matches:
                                # Clean up the URL
                                url = match.strip().rstrip('.,;:)')
                                if len(url) > 10:  # Filter out short matches
                                    all_urls.add(url)
                                    
                                    # Check if it's an API endpoint
                                    if '/api/' in url.lower() or 'api.' in url.lower():
                                        api_endpoints.add(url)
                                    
                                    # Check for sensitive keywords
                                    url_lower = url.lower()
                                    for keyword in SENSITIVE_URL_KEYWORDS:
                                        if keyword in url_lower:
                                            sensitive_urls.add(url)
                                            break
    
    except Exception as e:
        click.echo(f"𓆲 Warning: Could not fully analyze DEX: {e}", err=True)
    
    return {
        "urls": sorted(list(all_urls)),
        "api_endpoints": sorted(list(api_endpoints)),
        "sensitive_urls": sorted(list(sensitive_urls))
    }


def extract_apk_info(apk_path: str, deep_analysis: bool = False) -> dict:
    """
    Extract all relevant information from an APK file.
    
    Args:
        apk_path: Path to the APK file
        deep_analysis: If True, also extract URLs from DEX
        
    Returns:
        Dictionary containing extracted APK information
    """
    apk = APK(apk_path)
    
    info = {
        # Metadata
        "package_name": apk.get_package(),
        "version_code": apk.get_androidversion_code(),
        "version_name": apk.get_androidversion_name(),
        "app_name": apk.get_app_name(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "max_sdk": apk.get_max_sdk_version(),
        
        # Permissions
        "permissions": list(apk.get_permissions()),
        
        # Components
        "activities": list(apk.get_activities()),
        "services": list(apk.get_services()),
        "receivers": list(apk.get_receivers()),
        "providers": list(apk.get_providers()),
    }
    
    # Identify dangerous permissions
    info["dangerous_permissions"] = [
        p for p in info["permissions"] if p in DANGEROUS_PERMISSIONS
    ]
    
    # Deep analysis - extract URLs from DEX
    if deep_analysis:
        dex_info = extract_urls_from_dex(apk_path)
        info["urls"] = dex_info["urls"]
        info["api_endpoints"] = dex_info["api_endpoints"]
        info["sensitive_urls"] = dex_info["sensitive_urls"]
    
    return info


def compare_lists(old_list: list, new_list: list) -> dict:
    """Compare two lists and return added/removed items."""
    old_set = set(old_list)
    new_set = set(new_list)
    
    return {
        "added": sorted(list(new_set - old_set)),
        "removed": sorted(list(old_set - new_set)),
        "unchanged": sorted(list(old_set & new_set))
    }


def get_risk_level(diff: dict) -> dict:
    """Analyze diff and return risk assessment."""
    risks = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }
    
    # Check dangerous permissions
    added_permissions = diff.get("permissions", {}).get("added", [])
    for perm in added_permissions:
        if perm in DANGEROUS_PERMISSIONS:
            risks["critical"].append({
                "type": "permission",
                "item": perm,
                "description": DANGEROUS_PERMISSIONS[perm],
                "message": f"𓆲 صلاحية خطيرة جديدة: {DANGEROUS_PERMISSIONS[perm]}"
            })
    
    # Check new URLs (potential new attack surface)
    added_urls = diff.get("urls", {}).get("added", [])
    added_sensitive = diff.get("sensitive_urls", {}).get("added", [])
    
    for url in added_sensitive:
        risks["high"].append({
            "type": "sensitive_url",
            "item": url,
            "message": f"𓅆 رابط حساس جديد: {url}"
        })
    
    # Check new API endpoints
    added_apis = diff.get("api_endpoints", {}).get("added", [])
    for api in added_apis:
        if api not in added_sensitive:
            risks["medium"].append({
                "type": "api_endpoint",
                "item": api,
                "message": f"⌘ نقطة API جديدة: {api}"
            })
    
    # Check new components
    added_activities = diff.get("activities", {}).get("added", [])
    added_services = diff.get("services", {}).get("added", [])
    
    for activity in added_activities:
        risks["low"].append({
            "type": "activity",
            "item": activity,
            "message": f"𓅂 نشاط جديد: {activity}"
        })
    
    for service in added_services:
        risks["low"].append({
            "type": "service",
            "item": service,
            "message": f"⬢ خدمة جديدة: {service}"
        })
    
    return risks


def compare_apks(old_info: dict, new_info: dict) -> dict:
    """Compare two APK info dictionaries and return differences."""
    diff = {
        "metadata": {
            "old": {
                "package_name": old_info["package_name"],
                "version_code": old_info["version_code"],
                "version_name": old_info["version_name"],
                "app_name": old_info["app_name"],
                "min_sdk": old_info["min_sdk"],
                "target_sdk": old_info["target_sdk"],
            },
            "new": {
                "package_name": new_info["package_name"],
                "version_code": new_info["version_code"],
                "version_name": new_info["version_name"],
                "app_name": new_info["app_name"],
                "min_sdk": new_info["min_sdk"],
                "target_sdk": new_info["target_sdk"],
            }
        },
        "permissions": compare_lists(old_info["permissions"], new_info["permissions"]),
        "dangerous_permissions": compare_lists(
            old_info.get("dangerous_permissions", []), 
            new_info.get("dangerous_permissions", [])
        ),
        "activities": compare_lists(old_info["activities"], new_info["activities"]),
        "services": compare_lists(old_info["services"], new_info["services"]),
        "receivers": compare_lists(old_info["receivers"], new_info["receivers"]),
        "providers": compare_lists(old_info["providers"], new_info["providers"]),
    }
    
    # Compare URLs if available
    if "urls" in old_info and "urls" in new_info:
        diff["urls"] = compare_lists(old_info["urls"], new_info["urls"])
        diff["api_endpoints"] = compare_lists(
            old_info.get("api_endpoints", []), 
            new_info.get("api_endpoints", [])
        )
        diff["sensitive_urls"] = compare_lists(
            old_info.get("sensitive_urls", []),
            new_info.get("sensitive_urls", [])
        )
    
    # Calculate risk level
    diff["risks"] = get_risk_level(diff)
    
    return diff


def print_section(title: str, items: list, indent: int = 2):
    """Print a section with a title and list of items."""
    click.echo(f"\n{'=' * 60}")
    click.echo(f"𓅃 {title}")
    click.echo('=' * 60)
    
    if not items:
        click.echo(f"{' ' * indent}(لا يوجد)")
        return
    
    for item in items:
        click.echo(f"{' ' * indent}> {item}")
    
    click.echo(f"\n  Total: {len(items)}")


def print_diff_section(title: str, diff: dict, indent: int = 2, highlight_dangerous: bool = False):
    """Print a diff section with added/removed items."""
    click.echo(f"\n{'=' * 60}")
    click.echo(f"𓅃 {title}")
    click.echo('=' * 60)
    
    added = diff.get("added", [])
    removed = diff.get("removed", [])
    
    if not added and not removed:
        click.echo(f"{' ' * indent}𓅓 لا توجد تغييرات")
        return
    
    if added:
        click.secho(f"\n{' ' * indent}𓅈 Added ({len(added)}):", fg='green', bold=True)
        for item in added:
            # Check if this is a dangerous permission
            if highlight_dangerous and item in DANGEROUS_PERMISSIONS:
                click.secho(f"{' ' * indent}  [+] 𓆲 {item}", fg='red', bold=True, blink=True)
                click.secho(f"{' ' * indent}      > {DANGEROUS_PERMISSIONS[item]}", fg='yellow')
            else:
                click.secho(f"{' ' * indent}  [+] {item}", fg='green')
    
    if removed:
        click.secho(f"\n{' ' * indent}𓅉 Removed ({len(removed)}):", fg='red', bold=True)
        for item in removed:
            click.secho(f"{' ' * indent}  [-] {item}", fg='red')


def print_risks(risks: dict):
    """Print risk assessment with colors."""
    click.echo(f"\n{'=' * 60}")
    click.echo("𓆲 Risk Assessment")
    click.echo('=' * 60)
    
    has_risks = False
    
    if risks["critical"]:
        has_risks = True
        click.secho("\n  𓆲 CRITICAL:", fg='red', bold=True, blink=True)
        for risk in risks["critical"]:
            click.secho(f"     > {risk['message']}", fg='red')
    
    if risks["high"]:
        has_risks = True
        click.secho("\n  𓅆 HIGH:", fg='yellow', bold=True)
        for risk in risks["high"]:
            click.secho(f"     > {risk['message']}", fg='yellow')
    
    if risks["medium"]:
        has_risks = True
        click.secho("\n  ⬢ MEDIUM:", fg='cyan')
        for risk in risks["medium"]:
            click.echo(f"     > {risk['message']}")
    
    if risks["low"]:
        has_risks = True
        click.secho("\n  𓅓 LOW:", fg='blue')
        for risk in risks["low"][:5]:  # Show only first 5
            click.echo(f"     > {risk['message']}")
        if len(risks["low"]) > 5:
            click.echo(f"     ... and {len(risks['low']) - 5} more")
    
    if not has_risks:
        click.secho("\n  𓅓 No significant risks detected", fg='green')


def generate_html_report(diff: dict, old_path: str, new_path: str) -> str:
    """Generate a beautiful HTML report from the diff."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risks = diff.get("risks", {"critical": [], "high": [], "medium": [], "low": []})
    
    html = f'''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Comparison Report - falcon0x1</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #eee;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            background: linear-gradient(90deg, #00d4ff, #7c3aed, #f472b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #888;
            font-size: 0.9em;
        }}
        
        .header .author {{
            margin-top: 15px;
            color: #7c3aed;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .risk-banner {{
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .risk-banner.critical {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(185, 28, 28, 0.3));
            border: 2px solid #ef4444;
            animation: pulse 2s infinite;
        }}
        
        .risk-banner.high {{
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.3), rgba(217, 119, 6, 0.3));
            border: 2px solid #f59e0b;
        }}
        
        .risk-banner.safe {{
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(22, 163, 74, 0.2));
            border: 2px solid #22c55e;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        .risk-banner h2 {{
            font-size: 1.5em;
            margin-bottom: 10px;
        }}
        
        .risk-banner.critical h2 {{ color: #ef4444; }}
        .risk-banner.high h2 {{ color: #f59e0b; }}
        .risk-banner.safe h2 {{ color: #22c55e; }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .meta-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .meta-card.old {{
            border-left: 4px solid #ef4444;
        }}
        
        .meta-card.new {{
            border-left: 4px solid #22c55e;
        }}
        
        .meta-card h3 {{
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .meta-card.old h3 {{ color: #ef4444; }}
        .meta-card.new h3 {{ color: #22c55e; }}
        
        .meta-item {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        .meta-item:last-child {{
            border-bottom: none;
        }}
        
        .meta-label {{
            color: #888;
        }}
        
        .meta-value {{
            font-family: 'Consolas', monospace;
            color: #00d4ff;
        }}
        
        .section {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .section.danger {{
            border-color: #ef4444;
            background: rgba(239, 68, 68, 0.1);
        }}
        
        .section h2 {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .badge {{
            font-size: 0.7em;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: normal;
        }}
        
        .badge.added {{
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
        }}
        
        .badge.removed {{
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }}
        
        .badge.danger {{
            background: rgba(239, 68, 68, 0.3);
            color: #ef4444;
            animation: pulse 1s infinite;
        }}
        
        .diff-list {{
            list-style: none;
        }}
        
        .diff-item {{
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 8px;
            font-family: 'Consolas', monospace;
            font-size: 0.9em;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .diff-item.added {{
            background: rgba(34, 197, 94, 0.1);
            border-right: 3px solid #22c55e;
            color: #22c55e;
        }}
        
        .diff-item.removed {{
            background: rgba(239, 68, 68, 0.1);
            border-right: 3px solid #ef4444;
            color: #ef4444;
        }}
        
        .diff-item.danger {{
            background: rgba(239, 68, 68, 0.2);
            border-right: 5px solid #ef4444;
            color: #fff;
            animation: pulse 2s infinite;
        }}
        
        .diff-item .danger-label {{
            background: #ef4444;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-right: 10px;
        }}
        
        .diff-icon {{
            font-size: 1.2em;
            font-weight: bold;
        }}
        
        .no-changes {{
            text-align: center;
            padding: 30px;
            color: #888;
        }}
        
        .no-changes .icon {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .url-item {{
            word-break: break-all;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 30px;
        }}
        
        .summary-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
        }}
        
        .summary-card .label {{
            color: #888;
            font-size: 0.85em;
            margin-top: 5px;
        }}
        
        .summary-card.added .number {{ color: #22c55e; }}
        .summary-card.removed .number {{ color: #ef4444; }}
        .summary-card.danger .number {{ color: #ef4444; animation: pulse 1s infinite; }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.85em;
        }}
        
        @media (max-width: 768px) {{
            .meta-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>𓅃 APK Deep Analysis Report</h1>
            <p class="subtitle">تقرير التحليل العميق لملفات APK</p>
            <p class="author">By falcon0x1 𓅃</p>
            <p class="subtitle" style="margin-top: 10px;">Generated: {timestamp}</p>
        </div>
'''
    
    # Risk Banner
    critical_count = len(risks.get("critical", []))
    high_count = len(risks.get("high", []))
    
    if critical_count > 0:
        html += f'''
        <div class="risk-banner critical">
            <h2>𓆲 CRITICAL: {critical_count} dangerous changes detected!</h2>
            <p>This update contains dangerous changes that require careful review</p>
        </div>
'''
    elif high_count > 0:
        html += f'''
        <div class="risk-banner high">
            <h2>𓅆 WARNING: {high_count} high-risk changes detected</h2>
            <p>Review recommended before use</p>
        </div>
'''
    else:
        html += '''
        <div class="risk-banner safe">
            <h2>𓅓 SAFE: No significant risks detected</h2>
            <p>Changes appear normal</p>
        </div>
'''
    
    # Metadata cards
    html += f'''
        <div class="meta-grid">
            <div class="meta-card old">
                <h3>𓅉 Old APK</h3>
                <div class="meta-item">
                    <span class="meta-label">Package</span>
                    <span class="meta-value">{diff['metadata']['old']['package_name']}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Version</span>
                    <span class="meta-value">{diff['metadata']['old']['version_name']} ({diff['metadata']['old']['version_code']})</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Min SDK</span>
                    <span class="meta-value">{diff['metadata']['old']['min_sdk']}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Target SDK</span>
                    <span class="meta-value">{diff['metadata']['old']['target_sdk']}</span>
                </div>
            </div>
            
            <div class="meta-card new">
                <h3>𓅈 New APK</h3>
                <div class="meta-item">
                    <span class="meta-label">Package</span>
                    <span class="meta-value">{diff['metadata']['new']['package_name']}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Version</span>
                    <span class="meta-value">{diff['metadata']['new']['version_name']} ({diff['metadata']['new']['version_code']})</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Min SDK</span>
                    <span class="meta-value">{diff['metadata']['new']['min_sdk']}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Target SDK</span>
                    <span class="meta-value">{diff['metadata']['new']['target_sdk']}</span>
                </div>
            </div>
        </div>
'''
    
    # Helper function to generate section HTML
    def generate_section(title: str, icon: str, diff_data: dict, is_danger: bool = False, is_url: bool = False) -> str:
        added = diff_data.get("added", [])
        removed = diff_data.get("removed", [])
        
        danger_class = "danger" if is_danger and added else ""
        danger_badge = '<span class="badge danger">𓆲 DANGER</span>' if is_danger and added else ""
        
        section_html = f'''
        <div class="section {danger_class}">
            <h2>
                {icon} {title}
                <span class="badge added">+{len(added)}</span>
                <span class="badge removed">-{len(removed)}</span>
                {danger_badge}
            </h2>
'''
        
        if not added and not removed:
            section_html += '''
            <div class="no-changes">
                <div class="icon">𓅓</div>
                <p>No changes</p>
            </div>
'''
        else:
            section_html += '<ul class="diff-list">'
            for item in added:
                is_dangerous_perm = item in DANGEROUS_PERMISSIONS if is_danger else False
                item_class = "diff-item added danger" if is_dangerous_perm else "diff-item added"
                danger_label = f'<span class="danger-label">{DANGEROUS_PERMISSIONS.get(item, "𓆲")}</span>' if is_dangerous_perm else ""
                url_class = "url-item" if is_url else ""
                
                section_html += f'''
                <li class="{item_class}">
                    <span class="diff-icon">+</span>
                    {danger_label}
                    <span class="{url_class}">{item}</span>
                </li>
'''
            for item in removed:
                url_class = "url-item" if is_url else ""
                section_html += f'''
                <li class="diff-item removed">
                    <span class="diff-icon">-</span>
                    <span class="{url_class}">{item}</span>
                </li>
'''
            section_html += '</ul>'
        
        section_html += '</div>'
        return section_html
    
    html += generate_section("Permissions", "𓆲", diff["permissions"], is_danger=True)
    html += generate_section("Activities", "𓅂", diff["activities"])
    html += generate_section("Services", "⬢", diff["services"])
    html += generate_section("Receivers", "⌘", diff["receivers"])
    html += generate_section("Providers", "𓅓", diff["providers"])
    
    # URL sections if available
    if "urls" in diff:
        html += generate_section("URLs", "⌘", diff["urls"], is_url=True)
    if "api_endpoints" in diff:
        html += generate_section("API Endpoints", "𓅆", diff["api_endpoints"], is_url=True)
    if "sensitive_urls" in diff:
        html += generate_section("Sensitive URLs", "𓆲", diff["sensitive_urls"], is_danger=True, is_url=True)
    
    # Calculate totals
    total_added = sum(len(diff[key]["added"]) for key in ["permissions", "activities", "services", "receivers", "providers"])
    total_removed = sum(len(diff[key]["removed"]) for key in ["permissions", "activities", "services", "receivers", "providers"])
    dangerous_added = len(diff.get("dangerous_permissions", {}).get("added", []))
    
    html += f'''
        <div class="summary">
            <div class="summary-card {"danger" if dangerous_added > 0 else ""}">
                <div class="number">{dangerous_added}</div>
                <div class="label">Dangerous Permissions</div>
            </div>
            <div class="summary-card added">
                <div class="number">{total_added}</div>
                <div class="label">Total Added</div>
            </div>
            <div class="summary-card removed">
                <div class="number">{total_removed}</div>
                <div class="label">Total Removed</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #00d4ff;">{len(diff.get("urls", {{}}).get("added", []))}</div>
                <div class="label">New URLs</div>
            </div>
        </div>
        
        <div class="footer">
            <p>APK Deep Analyzer | Powered by Androguard</p>
            <p>Created by falcon0x1 𓅃</p>
        </div>
    </div>
</body>
</html>
'''
    
    return html


@click.group()
def cli():
    """
    𓅃 APK Analyzer & Comparator - By falcon0x1
    
    A powerful tool to analyze and compare Android APK files
    with deep DEX analysis and risk assessment.
    """
    pass


@cli.command('analyze')
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--deep', 'deep_analysis', is_flag=True, help='Enable deep DEX analysis (extract URLs)')
def analyze(apk_path: str, output_json: bool, deep_analysis: bool):
    """
    Analyze a single APK file.
    
    APK_PATH: Path to the APK file to analyze.
    
    Examples:
        python apk_analyzer.py analyze app.apk
        python apk_analyzer.py analyze app.apk --deep
        python apk_analyzer.py analyze app.apk --json --deep
    """
    try:
        click.echo(f"\n𓅃 Analyzing: {apk_path}")
        if deep_analysis:
            click.echo("𓆲 Deep analysis (DEX) enabled...")
        click.echo("-" * 60)
        
        info = extract_apk_info(apk_path, deep_analysis=deep_analysis)
        
        if output_json:
            click.echo(json.dumps(info, indent=2, ensure_ascii=False))
            return
        
        # Print Metadata
        click.echo("\n" + "=" * 60)
        click.echo("𓅃 Metadata")
        click.echo("=" * 60)
        click.echo(f"  Package Name:  {info['package_name']}")
        click.echo(f"  App Name:      {info['app_name']}")
        click.echo(f"  Version Code:  {info['version_code']}")
        click.echo(f"  Version Name:  {info['version_name']}")
        click.echo(f"  Min SDK:       {info['min_sdk']}")
        click.echo(f"  Target SDK:    {info['target_sdk']}")
        if info['max_sdk']:
            click.echo(f"  Max SDK:       {info['max_sdk']}")
        
        print_section("Permissions", info['permissions'])
        
        # Dangerous permissions with highlighting
        if info.get('dangerous_permissions'):
            click.echo(f"\n{'=' * 60}")
            click.secho("𓆲 Dangerous Permissions", fg='red', bold=True)
            click.echo('=' * 60)
            for perm in info['dangerous_permissions']:
                click.secho(f"  𓆲 {perm}", fg='red')
                click.secho(f"     > {DANGEROUS_PERMISSIONS[perm]}", fg='yellow')
        
        print_section("Activities", info['activities'])
        print_section("Services", info['services'])
        print_section("Broadcast Receivers", info['receivers'])
        print_section("Content Providers", info['providers'])
        
        # Deep analysis results
        if deep_analysis:
            if info.get('urls'):
                print_section("URLs", info['urls'])
            if info.get('api_endpoints'):
                print_section("API Endpoints", info['api_endpoints'])
            if info.get('sensitive_urls'):
                click.echo(f"\n{'=' * 60}")
                click.secho("𓆲 Sensitive URLs", fg='yellow', bold=True)
                click.echo('=' * 60)
                for url in info['sensitive_urls']:
                    click.secho(f"  𓅆 {url}", fg='yellow')
        
        # Summary
        click.echo("\n" + "=" * 60)
        click.echo("𓅃 Summary")
        click.echo("=" * 60)
        click.echo(f"  Permissions:    {len(info['permissions'])}")
        click.secho(f"  Dangerous:      {len(info.get('dangerous_permissions', []))}", fg='red' if info.get('dangerous_permissions') else 'green')
        click.echo(f"  Activities:     {len(info['activities'])}")
        click.echo(f"  Services:       {len(info['services'])}")
        click.echo(f"  Receivers:      {len(info['receivers'])}")
        click.echo(f"  Providers:      {len(info['providers'])}")
        if deep_analysis:
            click.echo(f"  URLs:           {len(info.get('urls', []))}")
        click.echo()
        
    except Exception as e:
        click.echo(f"\n𓆲 Error: {str(e)}", err=True)
        raise click.Abort()


@cli.command('compare')
@click.argument('apk_old', type=click.Path(exists=True))
@click.argument('apk_new', type=click.Path(exists=True))
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--html', 'output_html', type=click.Path(), help='Save report as HTML file')
@click.option('--deep', 'deep_analysis', is_flag=True, help='Enable deep DEX analysis')
def compare(apk_old: str, apk_new: str, output_json: bool, output_html: str, deep_analysis: bool):
    """
    Compare two APK files and show differences.
    
    APK_OLD: Path to the old/original APK file.
    APK_NEW: Path to the new/updated APK file.
    
    Examples:
        python apk_analyzer.py compare old.apk new.apk
        python apk_analyzer.py compare old.apk new.apk --deep
        python apk_analyzer.py compare old.apk new.apk --html report.html --deep
    """
    try:
        click.echo(f"\n𓅃 APK Deep Comparator - By falcon0x1")
        click.echo("=" * 60)
        click.echo(f"  𓅉 Old APK: {apk_old}")
        click.echo(f"  𓅈 New APK: {apk_new}")
        if deep_analysis:
            click.echo("  𓆲 Deep Analysis: Enabled")
        click.echo("-" * 60)
        
        click.echo("\n⌘ Analyzing files...")
        old_info = extract_apk_info(apk_old, deep_analysis=deep_analysis)
        new_info = extract_apk_info(apk_new, deep_analysis=deep_analysis)
        
        click.echo("⌘ Comparing...")
        diff = compare_apks(old_info, new_info)
        
        # JSON output
        if output_json:
            click.echo(json.dumps(diff, indent=2, ensure_ascii=False))
            return
        
        # HTML output
        if output_html:
            html_content = generate_html_report(diff, apk_old, apk_new)
            with open(output_html, 'w', encoding='utf-8') as f:
                f.write(html_content)
            click.secho(f"\n𓅓 Report saved to: {output_html}", fg='green', bold=True)
            return
        
        # Terminal output
        click.echo("\n" + "=" * 60)
        click.echo("𓅃 Comparison Results")
        click.echo("=" * 60)
        
        # Metadata comparison
        click.echo("\n𓅃 Metadata Changes:")
        old_meta = diff['metadata']['old']
        new_meta = diff['metadata']['new']
        
        if old_meta['version_code'] != new_meta['version_code']:
            click.echo(f"  Version: {old_meta['version_code']} > {new_meta['version_code']}")
        if old_meta['target_sdk'] != new_meta['target_sdk']:
            click.echo(f"  Target SDK: {old_meta['target_sdk']} > {new_meta['target_sdk']}")
        
        # Risk Assessment
        print_risks(diff.get("risks", {}))
        
        # Diff sections
        print_diff_section("Permissions", diff['permissions'], highlight_dangerous=True)
        print_diff_section("Activities", diff['activities'])
        print_diff_section("Services", diff['services'])
        print_diff_section("Receivers", diff['receivers'])
        print_diff_section("Providers", diff['providers'])
        
        # URL comparisons if deep analysis
        if deep_analysis and "urls" in diff:
            print_diff_section("URLs", diff['urls'])
            print_diff_section("API Endpoints", diff['api_endpoints'])
            if diff.get("sensitive_urls", {}).get("added"):
                click.echo(f"\n{'=' * 60}")
                click.secho("𓆲 New Sensitive URLs", fg='yellow', bold=True)
                click.echo('=' * 60)
                for url in diff['sensitive_urls']['added']:
                    click.secho(f"  𓅆 [+] {url}", fg='yellow')
        
        # Summary
        total_added = sum(len(diff[key]["added"]) for key in ["permissions", "activities", "services", "receivers", "providers"])
        total_removed = sum(len(diff[key]["removed"]) for key in ["permissions", "activities", "services", "receivers", "providers"])
        
        click.echo("\n" + "=" * 60)
        click.echo("𓅃 Change Summary")
        click.echo("=" * 60)
        
        dangerous_added = len(diff.get("dangerous_permissions", {}).get("added", []))
        if dangerous_added > 0:
            click.secho(f"  𓆲 Dangerous Permissions: {dangerous_added}", fg='red', bold=True)
        
        click.secho(f"  𓅈 Total Added: {total_added}", fg='green')
        click.secho(f"  𓅉 Total Removed: {total_removed}", fg='red')
        
        if deep_analysis and "urls" in diff:
            click.echo(f"  ⌘ New URLs: {len(diff['urls']['added'])}")
        
        click.echo()
        
    except Exception as e:
        click.echo(f"\n𓆲 Error: {str(e)}", err=True)
        raise click.Abort()


if __name__ == "__main__":
    cli()
