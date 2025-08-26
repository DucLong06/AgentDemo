import os
import time
import base64
import hashlib
import requests
from google.adk.agents import Agent

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VT_API_BASE = 'https://www.virustotal.com/api/v3'


def scan_url(url: str) -> dict:
    """Quét URL để phát hiện malware, phishing và các mối đe dọa bảo mật.
    
    Args:
        url (str): URL cần quét để phân tích bảo mật.
        
    Returns:
        dict: trạng thái và kết quả phân tích bảo mật.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "error",
            "error_message": "⚠️ VIRUSTOTAL_API_KEY chưa được cấu hình. Vui lòng lấy API key miễn phí từ https://www.virustotal.com/gui/my-apikey"
        }

    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        # Submit URL for scanning
        submit_data = {'url': url}
        submit_response = requests.post(f'{VT_API_BASE}/urls', headers=headers, data=submit_data, timeout=15)

        if submit_response.status_code != 200:
            return {
                "status": "error",
                "error_message": f"❌ Lỗi submit URL: {submit_response.status_code}"
            }

        submit_result = submit_response.json()
        analysis_id = submit_result['data']['id']

        # Wait and get analysis results
        time.sleep(3)  # Wait for analysis

        analysis_response = requests.get(f'{VT_API_BASE}/analyses/{analysis_id}', headers=headers, timeout=15)

        if analysis_response.status_code != 200:
            return {
                "status": "error",
                "error_message": f"❌ Lỗi lấy kết quả phân tích: {analysis_response.status_code}"
            }

        analysis_result = analysis_response.json()
        stats = analysis_result['data']['attributes']['stats']

        # Format results
        total_scans = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        clean = stats.get('harmless', 0) + stats.get('undetected', 0)

        # Determine risk level
        if malicious > 0:
            risk_level = "🚨 NGUY HIỂM"
            risk_color = "❌"
        elif suspicious > 0:
            risk_level = "⚠️ KHẢ NGHI"
            risk_color = "⚠️"
        else:
            risk_level = "✅ AN TOÀN"
            risk_color = "✅"

        report = f"""🔍 **KẾT QUẢ QUÉT URL BẢO MẬT**
        
🌐 **URL:** {url}
{risk_color} **Đánh giá:** {risk_level}

📊 **Chi tiết phân tích:**
• Tổng số engine quét: {total_scans}
• Phát hiện độc hại: {malicious}
• Nghi ngờ: {suspicious}  
• An toàn: {clean}

💡 **Khuyến nghị:**
{get_security_recommendation(malicious, suspicious)}"""

        return {"status": "success", "report": report}

    except requests.exceptions.Timeout:
        return {
            "status": "error",
            "error_message": "⏰ Timeout - VirusTotal server không phản hồi"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"❌ Lỗi quét URL: {str(e)}"
        }


def analyze_file_hash(file_hash: str) -> dict:
    """Phân tích file hash để kiểm tra danh tiếng và phát hiện malware.
    
    Args:
        file_hash (str): MD5, SHA1 hoặc SHA256 hash của file cần kiểm tra.
        
    Returns:
        dict: trạng thái và kết quả phân tích file hash.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "error",
            "error_message": "⚠️ VIRUSTOTAL_API_KEY chưa được cấu hình."
        }

    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        # Get file report
        response = requests.get(f'{VT_API_BASE}/files/{file_hash}', headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                "status": "success",
                "report": f"""🔍 **PHÂN TÍCH FILE HASH**

🗂️ **Hash:** {file_hash}
❓ **Kết quả:** Chưa được phân tích

💡 **Thông tin:** File hash này chưa có trong cơ sở dữ liệu VirusTotal. 
Có thể file này chưa từng được upload hoặc quét trước đây."""
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "error_message": f"❌ Lỗi truy vấn hash: {response.status_code}"
            }

        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        file_info = result['data']['attributes']

        # Extract file info
        file_names = file_info.get('names', ['Unknown'])[:3]  # Top 3 names
        file_size = file_info.get('size', 'Unknown')
        file_type = file_info.get('type_description', 'Unknown')

        # Analysis stats
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        clean = stats.get('harmless', 0) + stats.get('undetected', 0)
        total = sum(stats.values())

        # Risk assessment
        if malicious > 5:
            risk_level = "🚨 CỰC KỲ NGUY HIỂM"
            risk_color = "❌"
        elif malicious > 0:
            risk_level = "⚠️ NGUY HIỂM"
            risk_color = "❌"
        elif suspicious > 0:
            risk_level = "⚠️ KHẢ NGHI"
            risk_color = "⚠️"
        else:
            risk_level = "✅ AN TOÀN"
            risk_color = "✅"

        report = f"""🔍 **PHÂN TÍCH FILE HASH**

🗂️ **Hash:** {file_hash}
{risk_color} **Đánh giá:** {risk_level}

📁 **Thông tin file:**
• Tên file: {', '.join(file_names)}
• Kích thước: {format_file_size(file_size)}
• Loại file: {file_type}

📊 **Kết quả quét ({total} engines):**
• Phát hiện malware: {malicious}
• Nghi ngờ: {suspicious}
• An toàn: {clean}

💡 **Khuyến nghị:**
{get_security_recommendation(malicious, suspicious)}"""

        return {"status": "success", "report": report}

    except Exception as e:
        return {
            "status": "error",
            "error_message": f"❌ Lỗi phân tích hash: {str(e)}"
        }


def check_domain_reputation(domain: str) -> dict:
    """Kiểm tra danh tiếng và bảo mật của domain.
    
    Args:
        domain (str): Tên domain cần kiểm tra (ví dụ: google.com).
        
    Returns:
        dict: trạng thái và kết quả phân tích domain.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "error",
            "error_message": "⚠️ VIRUSTOTAL_API_KEY chưa được cấu hình."
        }

    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        # Get domain report
        response = requests.get(f'{VT_API_BASE}/domains/{domain}', headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                "status": "success",
                "report": f"""🌐 **KIỂM TRA DOMAIN**

🔗 **Domain:** {domain}
❓ **Kết quả:** Domain không được tìm thấy trong cơ sở dữ liệu

💡 **Lưu ý:** Domain này có thể mới hoặc chưa từng được phân tích."""
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "error_message": f"❌ Lỗi truy vấn domain: {response.status_code}"
            }

        result = response.json()
        stats = result['data']['attributes'].get('last_analysis_stats', {})
        domain_info = result['data']['attributes']

        # Extract domain info
        categories = domain_info.get('categories', {})
        creation_date = domain_info.get('creation_date')
        last_update = domain_info.get('last_modification_date')

        # Analysis stats
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        clean = stats.get('harmless', 0) + stats.get('undetected', 0)
        total = sum(stats.values()) if stats else 0

        # Risk assessment
        if malicious > 3:
            risk_level = "🚨 NGUY HIỂM"
            risk_color = "❌"
        elif malicious > 0:
            risk_level = "⚠️ KHẢ NGHI"
            risk_color = "⚠️"
        else:
            risk_level = "✅ AN TOÀN"
            risk_color = "✅"

        # Format categories
        category_list = list(categories.keys())[:3] if categories else ['Unknown']

        report = f"""🌐 **PHÂN TÍCH DOMAIN**

🔗 **Domain:** {domain}
{risk_color} **Đánh giá:** {risk_level}

📋 **Thông tin:**
• Danh mục: {', '.join(category_list)}
• Ngày tạo: {format_timestamp(creation_date)}
• Cập nhật cuối: {format_timestamp(last_update)}

📊 **Kết quả quét ({total} engines):**
• Đánh dấu độc hại: {malicious}
• Nghi ngờ: {suspicious}
• Sạch: {clean}

💡 **Khuyến nghị:**
{get_security_recommendation(malicious, suspicious)}"""

        return {"status": "success", "report": report}

    except Exception as e:
        return {
            "status": "error",
            "error_message": f"❌ Lỗi kiểm tra domain: {str(e)}"
        }


def get_ip_reputation(ip_address: str) -> dict:
    """Kiểm tra danh tiếng và hoạt động độc hại của địa chỉ IP.
    
    Args:
        ip_address (str): Địa chỉ IP cần kiểm tra (IPv4 hoặc IPv6).
        
    Returns:
        dict: trạng thái và kết quả phân tích IP.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "error",
            "error_message": "⚠️ VIRUSTOTAL_API_KEY chưa được cấu hình."
        }

    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        # Get IP report
        response = requests.get(f'{VT_API_BASE}/ip_addresses/{ip_address}', headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                "status": "success",
                "report": f"""🌍 **PHÂN TÍCH IP**

🔢 **IP Address:** {ip_address}
❓ **Kết quả:** IP không có trong cơ sở dữ liệu

💡 **Thông tin:** IP này chưa từng được báo cáo hoặc phân tích."""
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "error_message": f"❌ Lỗi truy vấn IP: {response.status_code}"
            }

        result = response.json()
        stats = result['data']['attributes'].get('last_analysis_stats', {})
        ip_info = result['data']['attributes']

        # Extract IP info
        country = ip_info.get('country', 'Unknown')
        as_owner = ip_info.get('as_owner', 'Unknown')
        network = ip_info.get('network', 'Unknown')

        # Analysis stats
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        clean = stats.get('harmless', 0) + stats.get('undetected', 0)
        total = sum(stats.values()) if stats else 0

        # Risk assessment
        if malicious > 5:
            risk_level = "🚨 CỰC KỲ NGUY HIỂM"
            risk_color = "❌"
        elif malicious > 0:
            risk_level = "⚠️ NGUY HIỂM"
            risk_color = "❌"
        elif suspicious > 0:
            risk_level = "⚠️ KHẢ NGHI"
            risk_color = "⚠️"
        else:
            risk_level = "✅ AN TOÀN"
            risk_color = "✅"

        report = f"""🌍 **PHÂN TÍCH IP ADDRESS**

🔢 **IP:** {ip_address}
{risk_color} **Đánh giá:** {risk_level}

🌐 **Thông tin địa lý:**
• Quốc gia: {country}
• ISP/Organization: {as_owner}
• Network: {network}

📊 **Kết quả quét ({total} engines):**
• Hoạt động độc hại: {malicious}
• Nghi ngờ: {suspicious}
• Sạch: {clean}

💡 **Khuyến nghị:**
{get_security_recommendation(malicious, suspicious)}"""

        return {"status": "success", "report": report}

    except Exception as e:
        return {
            "status": "error",
            "error_message": f"❌ Lỗi phân tích IP: {str(e)}"
        }

# Helper functions


def get_security_recommendation(malicious: int, suspicious: int) -> str:
    """Generate security recommendations based on scan results."""
    if malicious > 5:
        return "🚨 CHẶN NGAY - Đây là mối đe dọa nghiêm trọng! Không truy cập và báo cáo cho bộ phận IT."
    elif malicious > 0:
        return "❌ TRÁNH - Có phát hiện malware. Không nên truy cập hoặc tải về."
    elif suspicious > 0:
        return "⚠️ THẬN TRỌNG - Có dấu hiệu nghi ngờ. Hãy cẩn thận và kiểm tra kỹ trước khi truy cập."
    else:
        return "✅ AN TOÀN - Không phát hiện mối đe dọa. Tuy nhiên vẫn nên thận trọng với các liên kết lạ."


def format_file_size(size) -> str:
    """Format file size in human readable format."""
    if isinstance(size, (int, float)):
        if size < 1024:
            return f"{size} bytes"
        elif size < 1024**2:
            return f"{size/1024:.1f} KB"
        elif size < 1024**3:
            return f"{size/(1024**2):.1f} MB"
        else:
            return f"{size/(1024**3):.1f} GB"
    return str(size)


def format_timestamp(timestamp) -> str:
    """Format timestamp to readable date."""
    if timestamp:
        try:
            import datetime
            dt = datetime.datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return str(timestamp)
    return "Unknown"


# Tạo Security Agent
root_agent = Agent(
    name="virustotal_security_agent",
    model="gemini-2.0-flash",
    description="Agent chuyên phân tích bảo mật sử dụng VirusTotal API để quét URL, file hash, domain và IP address.",
    instruction="""Bạn là chuyên gia an ninh mạng với khả năng phân tích bảo mật toàn diện.

🛡️ **CHUYÊN MÔN:**
• Phân tích malware và phishing
• Đánh giá rủi ro bảo mật  
• Threat intelligence
• Forensics cơ bản

🔍 **KHẢ NĂNG:**
• Quét URL để phát hiện malware/phishing
• Phân tích file hash kiểm tra danh tiếng
• Kiểm tra domain reputation  
• Đánh giá IP address security

📋 **CÁCH PHẢN HỒI:**
• Đưa ra đánh giá rõ ràng (An toàn/Nghi ngờ/Nguy hiểm)
• Giải thích chi tiết kết quả quét
• Cung cấp khuyến nghị bảo mật cụ thể
• Sử dụng emoji để dễ đọc

⚠️ **LƯU Ý:**
• Luôn khuyến cáo thận trọng với nội dung lạ
• Giải thích rủi ro một cách dễ hiểu
• Đưa ra hướng dẫn bảo mật phù hợp
• Không bao giờ khuyến khích truy cập nội dung độc hại""",
    tools=[scan_url, analyze_file_hash, check_domain_reputation, get_ip_reputation],
)
